//! Cryptographic suites.
use std::{future::Future, pin::Pin};

use futures::FutureExt;
use iref::Iri;
use ssi_rdf::IntoNQuads;
use ssi_vc::ProofValidity;
use ssi_verification_methods::{LinkedDataVerificationMethod, Signer, SignatureError, VerificationError, Verifier, SignatureAlgorithm};

use crate::{ProofConfiguration, UntypedProof};

// mod any;
mod dif;
mod unspecified;

#[cfg(feature = "w3c")]
mod w3c;

// pub use any::*;
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
    InvalidMessage(Box<dyn 'static + std::error::Error>)
}

pub trait FromRdfAndSuite<S> {
    // ...
}

/// Cryptographic suite.
pub trait CryptographicSuite: Sync + Sized {
    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm result.
    type Hashed: Sync + AsRef<[u8]>;

    /// Verification method.
    type VerificationMethod: Sync;

    /// Signature.
    type Signature;

    type SignatureProtocol: ssi_crypto::SignatureProtocol;

    /// Signature algorithm.
    type SignatureAlgorithm: SignatureAlgorithm<Self::VerificationMethod, Signature = Self::Signature, Protocol = Self::SignatureProtocol>;

    type Options;

    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError>;

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm;

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod, Self::SignatureProtocol>,
        params: ProofConfiguration<Self::VerificationMethod>,
        _options: Self::Options
    ) -> Result<UntypedProof<Self::VerificationMethod, Self::Signature>, SignatureError> {
        let algorithm = self.setup_signature_algorithm();
        
        let signature = signer.sign(
            algorithm,
            &params.verification_method,
            data.as_ref()
        )?;

        Ok(params.into_proof(signature))
    }

    fn verify_proof<'async_trait, 'd: 'async_trait, 'v: 'async_trait, 'p: 'async_trait>(
        &self,
        data: &'d Self::Hashed,
        verifier: &'v impl Verifier<Self::VerificationMethod>,
        proof: &'p UntypedProof<Self::VerificationMethod, Self::Signature>,
    ) -> Pin<Box<dyn 'async_trait + Send + Future<Output = Result<ProofValidity, VerificationError>>>>
    where
        Self::VerificationMethod: 'p,
        Self::SignatureAlgorithm: 'async_trait
    {
        let algorithm = self.setup_signature_algorithm();
        Box::pin(
            verifier
                .verify(
                    algorithm,
                    &proof.verification_method,
                    proof.proof_purpose,
                    data.as_ref(),
                    &proof.signature,
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
        params: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Transformed, Self::TransformError>;
}

/// SHA256-based input hashing algorithm used by many cryptographic suites.
fn sha256_hash<'a, T: CryptographicSuite>(
    data: &[u8],
    suite: &T,
    proof_configuration: &ProofConfiguration<T::VerificationMethod>,
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
                _options: &$crate::ProofConfiguration<<$ty as $crate::CryptographicSuite>::VerificationMethod>,
            ) -> Result<Self::Transformed, Self::TransformError> {
                Ok(data.canonical_form())
            }
        }
    };
}
