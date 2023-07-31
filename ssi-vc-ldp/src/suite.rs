//! Cryptographic suites.
use std::{future::Future, pin::Pin};

use futures::FutureExt;
use iref::Iri;
use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_rdf::IntoNQuads;
use ssi_vc::ProofValidity;
use ssi_verification_methods::LinkedDataVerificationMethod;

use crate::{ProofConfiguration, ProofOptions, ProofParameters, UntypedProof, UntypedProofRef};

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
}

/// Cryptographic suite.
pub trait CryptographicSuite: Sync + Sized {
    /// Transformation algorithm parameters.
    type TransformationParameters;

    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm parameters.
    type HashParameters;

    /// Hashing algorithm result.
    type Hashed: Sync + AsRef<[u8]>;

    /// Proof generation algorithm parameters.
    type ProofParameters: ProofParameters<Self::VerificationMethod>;

    type SigningParameters: SigningParameters<
        Self::TransformationParameters,
        Self::HashParameters,
        Self::ProofParameters,
    >;

    /// Combination of transformation parameters and hash parameters that can
    /// be used to verify a credential.
    type VerificationParameters: VerificationParameters<
        Self::TransformationParameters,
        Self::HashParameters,
    >;

    type VerificationMethod: Sync + ssi_crypto::VerificationMethod;

    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: Self::HashParameters,
    ) -> Result<Self::Hashed, HashError>;

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod>,
        params: Self::ProofParameters,
    ) -> Result<UntypedProof<Self::VerificationMethod>, SignatureError> {
        let (context, jws) = signer.sign(params.verification_method(), data.as_ref())?;
        Ok(params.into_proof(context, jws))
    }

    fn verify_proof<'async_trait, 'd: 'async_trait, 'v: 'async_trait, 'p: 'async_trait>(
        &self,
        data: &'d Self::Hashed,
        verifier: &'v impl Verifier<Self::VerificationMethod>,
        proof: UntypedProofRef<'p, Self::VerificationMethod>,
    ) -> Pin<Box<dyn 'async_trait + Send + Future<Output = Result<ProofValidity, VerificationError>>>>
    where
        Self::VerificationMethod: 'p,
    {
        Box::pin(
            verifier
                .verify(
                    proof.context,
                    proof.verification_method,
                    proof.proof_purpose,
                    data.as_ref(),
                    proof.signature,
                )
                .map(|result| result.map(Into::into)),
        )
    }
}

pub trait CryptographicSuiteInput<T>: CryptographicSuite {
    type TransformError;

    /// Transformation algorithm.
    fn transform(
        &self,
        data: T,
        params: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::TransformError>;
}

pub trait SigningParameters<T, H, P> {
    fn transformation_parameters(&self) -> T;

    fn hash_parameters(&self) -> H;

    fn into_proof_parameters(self) -> P;
}

impl<M: Clone + ssi_crypto::VerificationMethod>
    SigningParameters<(), ProofConfiguration<M>, ProofOptions<M>> for ProofOptions<M>
{
    fn transformation_parameters(&self) {}

    fn hash_parameters(&self) -> ProofConfiguration<M> {
        self.to_proof_configuration()
    }

    fn into_proof_parameters(self) -> ProofOptions<M> {
        self
    }
}

pub trait VerificationParameters<T, H> {
    fn transformation_parameters(&self) -> T;

    fn into_hash_parameters(self) -> H;
}

impl<M: Clone + ssi_crypto::VerificationMethod> VerificationParameters<(), ProofConfiguration<M>>
    for ProofOptions<M>
{
    fn transformation_parameters(&self) {}

    fn into_hash_parameters(self) -> ProofConfiguration<M> {
        self.into_proof_configuration()
    }
}

/// SHA256-based input hashing algorithm used by many cryptographic suites.
fn sha256_hash<T: CryptographicSuite>(
    data: &[u8],
    suite: &T,
    proof_configuration: ProofConfiguration<T::VerificationMethod>,
) -> [u8; 64]
where
    T::VerificationMethod: LinkedDataVerificationMethod,
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
                _options: (),
            ) -> Result<Self::Transformed, Self::TransformError> {
                Ok(data.canonical_form())
            }
        }
    };
}
