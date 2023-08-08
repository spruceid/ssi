//! Cryptographic suites.
use std::{future::Future, marker::PhantomData, pin::Pin, task};

use iref::Iri;
use pin_project::pin_project;
use ssi_rdf::IntoNQuads;
use ssi_vc::ProofValidity;
use ssi_verification_methods::{
    LinkedDataVerificationMethod, Referencable, SignatureAlgorithm, SignatureError, Signer,
    VerificationError, VerificationMethodRef, Verifier,
};

use crate::{
    utils::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture},
    ProofConfiguration, ProofConfigurationRef, UntypedProof, UntypedProofRef,
};

mod signatures;
pub use signatures::*;

mod any;
mod dif;
mod unspecified;

#[cfg(feature = "w3c")]
mod w3c;

pub use any::*;
pub use dif::*;
pub use unspecified::*;

#[cfg(feature = "w3c")]
pub use w3c::*;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid verification method")]
    InvalidVerificationMethod,

    #[error("message is too long")]
    TooLong,

    #[error("invalid message: {0}")]
    InvalidMessage(Box<dyn 'static + std::error::Error>),
}

pub trait FromRdfAndSuite<S> {
    // ...
}

/// Cryptographic suite.
pub trait CryptographicSuite: Sized {
    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm result.
    type Hashed: AsRef<[u8]>;

    /// Verification method.
    type VerificationMethod: Referencable;

    /// Signature.
    type Signature: Referencable;

    type SignatureProtocol: ssi_crypto::SignatureProtocol;

    /// Signature algorithm.
    type SignatureAlgorithm: SignatureAlgorithm<
        Self::VerificationMethod,
        Signature = Self::Signature,
        Protocol = Self::SignatureProtocol,
    >;

    type Options;

    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError>;

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm;

    fn generate_proof<
        'a,
        'max: 'a,
        S: Signer<Self::VerificationMethod, Self::SignatureProtocol>,
    >(
        &self,
        data: &'a Self::Hashed,
        signer: &'a S,
        params: ProofConfiguration<Self::VerificationMethod>,
        _options: Self::Options,
    ) -> GenerateProof<'max, 'a, Self, S> {
        let algorithm = self.setup_signature_algorithm();

        GenerateProof {
            signature: SelfRefFuture::new(
                params,
                Binder {
                    signer,
                    algorithm,
                    data: data.as_ref(),
                },
            ),
        }
    }

    fn verify_proof<'a, 'p, V: Verifier<Self::VerificationMethod>>(
        &self,
        data: &'a Self::Hashed,
        verifier: &'a V,
        proof: UntypedProofRef<'p, Self::VerificationMethod, Self::Signature>,
    ) -> VerifyProof<'a, 'p, Self, V>
    where
        <Self::VerificationMethod as Referencable>::Reference<'a>: VerificationMethodRef<'a>,
    {
        let algorithm = self.setup_signature_algorithm();
        VerifyProof {
            verify: verifier.verify(
                algorithm,
                None,
                Some(proof.verification_method),
                proof.proof_purpose,
                data.as_ref(),
                proof.signature,
            ),
        }
    }
}

struct SignBounded<'a, M, A, S>(PhantomData<(&'a (), M, A, S)>);

impl<
        'max,
        'a,
        M: 'a + 'max + Referencable,
        A: SignatureAlgorithm<M>,
        S: 'a + Signer<M, A::Protocol>,
    > UnboundedRefFuture<'a, 'max> for SignBounded<'a, M, A, S>
where
    A::Signature: 'a,
{
    type Owned = ProofConfiguration<M>;

    type Bound<'m: 'a> = S::Sign<'a, 'm, A> where 'max: 'm;

    type Output = Result<A::Signature, SignatureError>;
}

struct Binder<'a, A, S> {
    signer: &'a S,
    algorithm: A,
    data: &'a [u8],
}

impl<
        'max,
        'a,
        M: 'a + 'max + Referencable,
        A: SignatureAlgorithm<M>,
        S: Signer<M, A::Protocol>,
    > RefFutureBinder<'a, 'max, SignBounded<'a, M, A, S>> for Binder<'a, A, S>
where
    A::Signature: 'a,
{
    fn bind<'m>(context: Self, params: &'m ProofConfiguration<M>) -> S::Sign<'a, 'm, A>
    where
        'max: 'm,
    {
        context.signer.sign(
            context.algorithm,
            None,
            Some(params.verification_method.borrowed()),
            context.data,
        )
    }
}

#[pin_project]
pub struct GenerateProof<
    'max,
    'a,
    S: CryptographicSuite,
    T: 'a + Signer<S::VerificationMethod, S::SignatureProtocol>,
> where
    S::VerificationMethod: 'max + 'a,
    S::Signature: 'a,
{
    #[pin]
    signature:
        SelfRefFuture<'a, 'max, SignBounded<'a, S::VerificationMethod, S::SignatureAlgorithm, T>>,
}

impl<
        'max,
        'a,
        S: CryptographicSuite,
        T: 'a + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > Future for GenerateProof<'max, 'a, S, T>
where
    S::VerificationMethod: 'a,
{
    type Output = Result<UntypedProof<S::VerificationMethod, S::Signature>, SignatureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        // Ok(params.into_proof(signature))
        let this = self.project();
        let signature_state = this.signature.poll(cx);

        match signature_state {
            task::Poll::Pending => task::Poll::Pending,
            task::Poll::Ready((result, params)) => {
                task::Poll::Ready(result.map(|signature| params.into_proof(signature)))
            }
        }
    }
}

#[pin_project]
pub struct VerifyProof<'a, 'p, S: CryptographicSuite, V: Verifier<S::VerificationMethod>> {
    #[pin]
    verify: ssi_verification_methods::Verify<
        'a,
        'p,
        'p,
        S::VerificationMethod,
        V,
        S::SignatureAlgorithm,
    >,
}

impl<'a, 'p, S: CryptographicSuite, V: Verifier<S::VerificationMethod>> Future
    for VerifyProof<'a, 'p, S, V>
where
    <S::VerificationMethod as Referencable>::Reference<'a>: VerificationMethodRef<'a>,
{
    type Output = Result<ProofValidity, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.verify.poll(cx).map_ok(Into::into)
    }
}

pub trait CryptographicSuiteInput<T>: CryptographicSuite {
    type TransformError;

    /// Transformation algorithm.
    fn transform(
        &self,
        data: T,
        params: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Transformed, Self::TransformError>;
}

/// SHA256-based input hashing algorithm used by many cryptographic suites.
fn sha256_hash<'a, T: CryptographicSuite>(
    data: &[u8],
    suite: &T,
    proof_configuration: ProofConfigurationRef<'a, T::VerificationMethod>,
) -> [u8; 64]
where
    <T::VerificationMethod as Referencable>::Reference<'a>: LinkedDataVerificationMethod,
{
    let transformed_document_hash = ssi_crypto::hashes::sha256::sha256(data);
    let proof_config_hash: [u8; 32] = ssi_crypto::hashes::sha256::sha256(
        proof_configuration.quads(suite).into_nquads().as_bytes(),
    );
    let mut hash_data = [0u8; 64];
    hash_data[..32].copy_from_slice(&transformed_document_hash);
    hash_data[32..].copy_from_slice(&proof_config_hash);
    hash_data
}

/// `CryptographicSuiteInput` trait implementation for RDF dataset inputs
/// normalized using URDNA2015.
///
/// Many cryptographic suites take RDF datasets as input, then normalized with
/// the URDNA2015 canonicalization algorithm. This macro is used to
/// automatically write the `CryptographicSuiteInput` trait implementation.
#[macro_export]
macro_rules! impl_rdf_input_urdna2015 {
    ($ty:ident) => {
        impl<'a, V, I> $crate::CryptographicSuiteInput<ssi_rdf::DatasetWithEntryPoint<'a, V, I>>
            for $ty
        where
            V: rdf_types::Vocabulary<
                Type = rdf_types::literal::Type<
                    <V as rdf_types::IriVocabulary>::Iri,
                    <V as rdf_types::LanguageTagVocabulary>::LanguageTag,
                >,
                Value = String,
            >,
            I: rdf_types::ReverseTermInterpretation<
                Iri = V::Iri,
                BlankId = V::BlankId,
                Literal = V::Literal,
            >,
        {
            type TransformError = std::convert::Infallible;

            /// Transformation algorithm.
            fn transform(
                &self,
                data: ssi_rdf::DatasetWithEntryPoint<'a, V, I>,
                _options: $crate::ProofConfigurationRef<
                    <$ty as $crate::CryptographicSuite>::VerificationMethod,
                >,
            ) -> Result<Self::Transformed, Self::TransformError> {
                Ok(data.canonical_form())
            }
        }
    };
}
