//! Cryptographic suites.
use std::{convert::Infallible, future::Future, marker::PhantomData, pin::Pin, task};

use iref::Iri;
use linked_data::{to_quads, LinkedData, LinkedDataPredicateObjects, LinkedDataSubject};
use pin_project::pin_project;
use rdf_types::{
    generator,
    interpretation::{self, ReverseBlankIdInterpretation, ReverseIriInterpretation},
    ExportedFromVocabulary, Interpretation, InterpretationMut, Quad, ReverseLiteralInterpretation,
    Vocabulary,
};
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_rdf::urdna2015;
use ssi_vc::ProofValidity;
use ssi_verification_methods::{
    InvalidVerificationMethod, Referencable, SignatureAlgorithm, SignatureError, Signer,
    VerificationError, VerificationMethod, Verifier,
};

use crate::{
    signing::SignLinkedData, DataIntegrity, ProofConfiguration, ProofConfigurationCastError,
    ProofConfigurationRef, UntypedProof, UntypedProofRef,
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

    #[error("expected JSON object")] // TODO merge it with `InvalidData`.
    ExpectedJsonObject,

    #[error("invalid data")]
    InvalidData,

    #[error("unsupported input format")]
    UnsupportedInputFormat,

    #[error("invalid proof options: {0}")]
    InvalidProofOptions(InvalidOptions),

    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(InvalidVerificationMethod),

    #[error("internal error: `{0}`")]
    Internal(String),
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>>
    for TransformError
{
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(e) => Self::InvalidProofOptions(e),
        }
    }
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, Infallible>> for TransformError {
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, Infallible>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(_) => unreachable!(),
        }
    }
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

#[derive(Debug, thiserror::Error)]
pub enum InvalidOptions {
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<InvalidOptions> for VerificationError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => VerificationError::MissingPublicKey,
        }
    }
}

impl From<InvalidOptions> for SignatureError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => SignatureError::MissingPublicKey,
        }
    }
}

pub trait FromRdfAndSuite<S> {
    // ...
}

pub trait CryptographicSuiteOptions<T>: Referencable {
    /// Prepare the options to be put in the generated proof.
    ///
    /// This means filtering out options that should not appear in the proof, or
    /// adding in implicit options values used to generate the proof that should
    /// explicitly appear in the proof.
    fn prepare(&mut self, _suite: &T) {
        // filter nothing.
    }
}

impl<T: CryptographicSuite> CryptographicSuiteOptions<T> for () {}

/// Cryptographic suite.
pub trait CryptographicSuite: Sized {
    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm result.
    type Hashed: AsRef<[u8]>;

    /// Verification method.
    type VerificationMethod: VerificationMethod;

    /// Cryptography suite options used to generate the proof.
    type Options: CryptographicSuiteOptions<Self>;

    /// Signature.
    type Signature: Referencable;

    type MessageSignatureAlgorithm: Copy;

    type SignatureProtocol: ssi_crypto::SignatureProtocol<Self::MessageSignatureAlgorithm>;

    /// Signature algorithm.
    type SignatureAlgorithm: SignatureAlgorithm<
        Self::VerificationMethod,
        Options = Self::Options,
        Signature = Self::Signature,
        MessageSignatureAlgorithm = Self::MessageSignatureAlgorithm,
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

    fn generate_proof<'a, S>(
        &'a self,
        data: &'a Self::Hashed,
        signer: &'a S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> GenerateProof<'a, Self, S>
    where
        S: Signer<
            Self::VerificationMethod,
            Self::MessageSignatureAlgorithm,
            Self::SignatureProtocol,
        >,
    {
        let algorithm = self.setup_signature_algorithm();

        GenerateProof {
            suite: self,
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
    ) -> VerifyProof<'a, Self, V> {
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

impl<
        'a,
        M: 'a + Referencable,
        A: 'a + SignatureAlgorithm<M>,
        S: 'a + Signer<M, A::MessageSignatureAlgorithm, A::Protocol>,
    > UnboundedRefFuture<'a> for SignBounded<'a, M, A, S>
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

impl<
        'a,
        M: 'a + Referencable,
        A: 'a + SignatureAlgorithm<M>,
        S: Signer<M, A::MessageSignatureAlgorithm, A::Protocol>,
    > RefFutureBinder<'a, SignBounded<'a, M, A, S>> for Binder<'a, A, S>
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
    T: 'a + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
> where
    S::VerificationMethod: 'a,
    S::SignatureAlgorithm: 'a,
    S::Options: 'a,
    S::Signature: 'a,
{
    suite: &'a S,

    #[pin]
    signature: SelfRefFuture<'a, SignBounded<'a, S::VerificationMethod, S::SignatureAlgorithm, T>>,
}

impl<
        'a,
        S: CryptographicSuite,
        T: 'a + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    > Future for GenerateProof<'a, S, T>
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
            task::Poll::Ready((result, mut params)) => {
                params.options.prepare(this.suite);
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
{
    type Output = Result<ProofValidity, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.verify.poll(cx).map_ok(Into::into)
    }
}

pub trait CryptographicSuiteInput<T, C = ()>: CryptographicSuite {
    type Transform<'a>: 'a + Future<Output = Result<Self::Transformed, TransformError>>
    where
        Self: 'a,
        T: 'a,
        C: 'a;

    /// Transformation algorithm.
    fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: C,
        params: ProofConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Self::Transform<'a>
    where
        C: 'a;

    fn sign<'max, S>(
        self,
        input: T,
        context: C,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> SignLinkedData<'max, T, Self, C, S>
    where
        Self::VerificationMethod: 'max,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm,
                Self::SignatureProtocol,
            >,
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
    <T::VerificationMethod as Referencable>::Reference<'a>:
        LinkedDataPredicateObjects<interpretation::WithGenerator<generator::Blank>>,
    <T::Options as Referencable>::Reference<'a>:
        LinkedDataSubject<interpretation::WithGenerator<generator::Blank>>,
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

pub struct LinkedDataInput<I = (), V = ()> {
    pub vocabulary: V,
    pub interpretation: I,
}

impl Default for LinkedDataInput<interpretation::WithGenerator<rdf_types::generator::Blank>> {
    fn default() -> Self {
        Self::from_generator(rdf_types::generator::Blank::new())
    }
}

impl<G> LinkedDataInput<interpretation::WithGenerator<G>> {
    pub fn from_generator(generator: G) -> Self {
        Self {
            vocabulary: (),
            interpretation: interpretation::WithGenerator::new((), generator),
        }
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataInput<I, V>
where
    I: InterpretationMut<V>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
{
    pub fn new(vocabulary: V, interpretation: I) -> Self {
        Self {
            vocabulary,
            interpretation,
        }
    }

    /// Returns the list of quads in the dataset.
    ///
    /// The order in which quads are returned is unspecified.
    pub fn into_quads<T: LinkedData<I, V>>(
        mut self,
        input: &T,
    ) -> Result<Vec<Quad>, linked_data::IntoQuadsError> {
        linked_data::to_lexical_quads_with(&mut self.vocabulary, &mut self.interpretation, input)
    }

    /// Returns the canonical form of the dataset, in the N-Quads format.
    pub fn into_canonical_form<T: LinkedData<I, V>>(
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
        impl<'a, V: rdf_types::Vocabulary, I: rdf_types::Interpretation, T>
            $crate::CryptographicSuiteInput<T, $crate::LinkedDataInput<I, V>> for $ty
        where
            I: rdf_types::interpretation::InterpretationMut<V>
                + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
                + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
                + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
            V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
            T: linked_data::LinkedData<I, V>,
        {
            type Transform<'t> = ::std::future::Ready<Result<Self::Transformed, $crate::suite::TransformError>> where Self: 't, T: 't, $crate::LinkedDataInput<I, V>: 't;

            /// Transformation algorithm.
            fn transform<'t, 'c: 't>(
                &'t self,
                data: &'t T,
                context: $crate::LinkedDataInput<I, V>,
                _options: $crate::ProofConfigurationRef<'c,
                    <$ty as $crate::CryptographicSuite>::VerificationMethod,
                    <$ty as $crate::CryptographicSuite>::Options,
                >,
            ) -> Self::Transform<'t>
            where
                $crate::LinkedDataInput<I, V>: 't
            {
                ::std::future::ready(context.into_canonical_form(data).map_err(Into::into))
            }
        }
    };
}
