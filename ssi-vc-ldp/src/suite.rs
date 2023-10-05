//! Cryptographic suites.
use std::{future::Future, marker::PhantomData, pin::Pin, task};

use iref::Iri;
use linked_data::{to_quads, LinkedData, LinkedDataPredicateObjects, LinkedDataSubject};
use pin_project::pin_project;
use rdf_types::{
    interpretation::{ReverseBlankIdInterpretation, ReverseIriInterpretation},
    ExportedFromVocabulary, Interpretation, Quad, ReverseLiteralInterpretation, Vocabulary,
};
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_rdf::urdna2015;
use ssi_vc::ProofValidity;
use ssi_verification_methods::{
    Referencable, SignatureAlgorithm, SignatureError, Signer, VerificationError,
    VerificationMethod, VerificationMethodRef, Verifier,
};

use crate::{
    signing::SignLinkedData, DataIntegrity, ProofConfiguration, ProofConfigurationRef,
    UntypedProof, UntypedProofRef,
};

mod signatures;
pub use signatures::*;

#[cfg(feature = "w3c")]
mod w3c;
#[cfg(feature = "w3c")]
pub use w3c::*;

#[cfg(feature = "dif")]
mod dif;
#[cfg(feature = "dif")]
pub use dif::*;

mod unspecified;
pub use unspecified::*;

#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("RDF deserialization failed: {0}")]
    LinkedData(#[from] linked_data::IntoQuadsError),

    #[error("JSON serialization failed: {0}")]
    JsonSerialization(serde_json::Error),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("unsupported input format")]
    UnsupportedInputFormat,

    #[error("invalid verification method")]
    InvalidVerificationMethod,
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid verification method")]
    InvalidVerificationMethod,

    #[error("message is too long")]
    TooLong,

    #[error("invalid message: {0}")]
    InvalidMessage(Box<dyn 'static + std::error::Error>),

    #[error("invalid transformed input")]
    InvalidTransformedInput,
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
    type VerificationMethod: VerificationMethod;

    type Options: Referencable;

    /// Signature.
    type Signature: Referencable;

    type SignatureProtocol: ssi_crypto::SignatureProtocol;

    /// Signature algorithm.
    type SignatureAlgorithm: SignatureAlgorithm<
        Self::VerificationMethod,
        Options = Self::Options,
        Signature = Self::Signature,
        Protocol = Self::SignatureProtocol,
    >;

    fn iri(&self) -> &Iri;

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError>;

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm;

    fn generate_proof<'a, S: Signer<Self::VerificationMethod, Self::SignatureProtocol>>(
        &self,
        data: &'a Self::Hashed,
        signer: &'a S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> GenerateProof<'a, Self, S> {
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

    fn verify_proof<'a, 'p: 'a, V: Verifier<Self::VerificationMethod>>(
        &self,
        data: &'a Self::Hashed,
        verifier: &'a V,
        proof: UntypedProofRef<'p, Self::VerificationMethod, Self::Options, Self::Signature>,
    ) -> VerifyProof<'a, Self, V>
    where
        <Self::VerificationMethod as Referencable>::Reference<'a>: VerificationMethodRef<'a>,
    {
        let algorithm = self.setup_signature_algorithm();
        VerifyProof {
            verify: verifier.verify(
                algorithm,
                proof.options,
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

impl<'a, M: 'a + Referencable, A: 'a + SignatureAlgorithm<M>, S: 'a + Signer<M, A::Protocol>>
    UnboundedRefFuture<'a> for SignBounded<'a, M, A, S>
where
    A::Signature: 'a,
{
    type Owned = ProofConfiguration<M, A::Options>;

    type Bound<'m> = S::Sign<'m, A> where 'a: 'm;

    type Output = Result<A::Signature, SignatureError>;
}

struct Binder<'a, A, S> {
    signer: &'a S,
    algorithm: A,
    data: &'a [u8],
}

impl<'a, M: 'a + Referencable, A: 'a + SignatureAlgorithm<M>, S: Signer<M, A::Protocol>>
    RefFutureBinder<'a, SignBounded<'a, M, A, S>> for Binder<'a, A, S>
where
    A::Signature: 'a,
{
    fn bind<'m>(context: Self, params: &'m ProofConfiguration<M, A::Options>) -> S::Sign<'m, A>
    where
        'a: 'm,
    {
        context.signer.sign(
            context.algorithm,
            params.options.as_reference(),
            None,
            Some(params.verification_method.borrowed()),
            context.data,
        )
    }
}

#[pin_project]
pub struct GenerateProof<
    'a,
    S: CryptographicSuite,
    T: 'a + Signer<S::VerificationMethod, S::SignatureProtocol>,
> where
    S::VerificationMethod: 'a,
    S::SignatureAlgorithm: 'a,
    S::Options: 'a,
    S::Signature: 'a,
{
    #[pin]
    signature: SelfRefFuture<'a, SignBounded<'a, S::VerificationMethod, S::SignatureAlgorithm, T>>,
}

impl<'a, S: CryptographicSuite, T: 'a + Signer<S::VerificationMethod, S::SignatureProtocol>> Future
    for GenerateProof<'a, S, T>
where
    S::VerificationMethod: 'a,
{
    type Output =
        Result<UntypedProof<S::VerificationMethod, S::Options, S::Signature>, SignatureError>;

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
pub struct VerifyProof<'a, S: CryptographicSuite, V: Verifier<S::VerificationMethod>> {
    #[pin]
    verify: ssi_verification_methods::Verify<'a, S::VerificationMethod, V, S::SignatureAlgorithm>,
}

impl<'a, S: CryptographicSuite, V: 'a + Verifier<S::VerificationMethod>> Future
    for VerifyProof<'a, S, V>
where
    S::VerificationMethod: VerificationMethod,
    <S::VerificationMethod as Referencable>::Reference<'a>: VerificationMethodRef<'a>,
{
    type Output = Result<ProofValidity, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.verify.poll(cx).map_ok(Into::into)
    }
}

pub trait CryptographicSuiteInput<T, C = ()>: CryptographicSuite {
    /// Transformation algorithm.
    fn transform(
        &self,
        data: &T,
        context: C,
        params: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, TransformError>;

    fn sign<'max, S>(
        self,
        input: T,
        context: C,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> SignLinkedData<'max, T, Self, S>
    where
        Self::VerificationMethod: 'max,
        S: 'max + Signer<Self::VerificationMethod, Self::SignatureProtocol>,
    {
        DataIntegrity::sign(input, context, signer, self, params)
    }
}

/// SHA256-based input hashing algorithm used by many cryptographic suites.
fn sha256_hash<'a, T: CryptographicSuite>(
    data: &[u8],
    suite: &T,
    proof_configuration: ProofConfigurationRef<'a, T::VerificationMethod, T::Options>,
) -> [u8; 64]
where
    <T::VerificationMethod as Referencable>::Reference<'a>: LinkedDataPredicateObjects,
    <T::Options as Referencable>::Reference<'a>: LinkedDataSubject,
{
    let generator = rdf_types::generator::Blank::new();
    let proof_config_quads = to_quads(generator, &proof_configuration.with_suite(suite)).unwrap();
    let proof_config_normalized_quads =
        urdna2015::normalize(proof_config_quads.iter().map(Quad::as_quad_ref)).into_nquads();
    let proof_config_hash: [u8; 32] =
        ssi_crypto::hashes::sha256::sha256(proof_config_normalized_quads.as_bytes());

    let transformed_document_hash = ssi_crypto::hashes::sha256::sha256(data);

    let mut hash_data = [0u8; 64];
    hash_data[..32].copy_from_slice(&proof_config_hash);
    hash_data[32..].copy_from_slice(&transformed_document_hash);
    hash_data
}

pub struct LinkedDataInput<'a, V, I, G> {
    pub vocabulary: &'a mut V,
    pub interpretation: &'a mut I,
    pub generator: G,
}

impl Default for LinkedDataInput<'static, (), (), rdf_types::generator::Blank> {
    fn default() -> Self {
        Self {
            vocabulary: rdf_types::vocabulary::no_vocabulary_mut(),
            interpretation: rdf_types::vocabulary::no_vocabulary_mut(),
            generator: rdf_types::generator::Blank::new(),
        }
    }
}

impl<'a, V: Vocabulary, I: Interpretation, G> LinkedDataInput<'a, V, I, G>
where
    I: ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    G: rdf_types::Generator<()>,
{
    pub fn new(vocabulary: &'a mut V, interpretation: &'a mut I, generator: G) -> Self {
        Self {
            vocabulary,
            interpretation,
            generator,
        }
    }

    /// Returns the list of quads in the dataset.
    ///
    /// The order in which quads are returned is unspecified.
    pub fn into_quads<T: LinkedData<V, I>>(
        self,
        input: &T,
    ) -> Result<Vec<Quad>, linked_data::IntoQuadsError> {
        linked_data::to_lexical_quads_with(
            self.vocabulary,
            self.interpretation,
            self.generator,
            input,
        )
    }

    /// Returns the canonical form of the dataset, in the N-Quads format.
    pub fn into_canonical_form<T: LinkedData<V, I>>(
        self,
        input: &T,
    ) -> Result<String, linked_data::IntoQuadsError> {
        let quads = self.into_quads(input)?;
        Ok(
            ssi_rdf::urdna2015::normalize(quads.iter().map(|quad| quad.as_quad_ref()))
                .into_nquads(),
        )
    }
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
        impl<'a, V: rdf_types::Vocabulary, I: rdf_types::Interpretation, G, T>
            $crate::CryptographicSuiteInput<T, $crate::LinkedDataInput<'a, V, I, G>> for $ty
        where
            I: rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
                + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
                + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
            V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
            G: rdf_types::Generator<()>,
            T: linked_data::LinkedData<V, I>,
        {
            /// Transformation algorithm.
            fn transform(
                &self,
                data: &T,
                context: $crate::LinkedDataInput<'a, V, I, G>,
                _options: $crate::ProofConfigurationRef<
                    <$ty as $crate::CryptographicSuite>::VerificationMethod,
                    <$ty as $crate::CryptographicSuite>::Options,
                >,
            ) -> Result<Self::Transformed, $crate::suite::TransformError> {
                Ok(context.into_canonical_form(data)?)
            }
        }
    };
}
