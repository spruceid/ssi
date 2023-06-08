//! Cryptographic suites.

mod ed25519_signature_2020;

pub use ed25519_signature_2020::Ed25519Signature2020;
use ssi_crypto::VerifierProvider;
use ssi_vc::ProofValidity;
use treeldr_rust_prelude::iref::{Iri, IriBuf};

use crate::{
    DataIntegrity, LinkedDataCredential, LinkedDataCredentialContext, Proof, SignerProvider,
};

pub trait Type {
    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;
}

pub trait VerificationMethod {
    fn iri(&self) -> Iri;
}

impl VerificationMethod for IriBuf {
    fn iri(&self) -> Iri {
        self.as_iri()
    }
}

pub struct TransformationOptions<T> {
    pub type_: T,
}

impl<
        'n,
        T: LinkedDataCredential<Self>,
        S: VerifiableCryptographicSuite<M> + CryptographicSuiteInput<T, M, Self>,
        M,
        L,
        C,
        N,
        G,
    > ssi_vc::Context<DataIntegrity<T>, Proof<S, M>>
    for LinkedDataCredentialContext<'n, L, C, N, G>
{
    fn transform(
        &mut self,
        value: &DataIntegrity<T>,
        proof: &Proof<S, M>,
        parameters: &S::VerificationParameters,
    ) -> Result<S::Transformed, S::Error> {
        proof
            .type_
            .transform(self, &value.0, parameters.transformation_parameters())
    }
}

pub trait CryptographicSuiteInput<T, M, C>: CryptographicSuite<M> {
    /// Transformation algorithm.
    fn transform(
        &self,
        context: &mut C,
        data: &T,
        params: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error>;
}

pub trait VerificationParameters<T, H> {
    fn transformation_parameters(&self) -> T;

    fn into_hash_parameters(self) -> H;
}

/// Cryptographic suite.
///
/// The type parameter `T` is the type of documents on which the suite can be
/// applied.
pub trait CryptographicSuite<M>: Sized {
    /// Error that can be raised by the suite.
    type Error;

    /// Transformation algorithm parameters.
    type TransformationParameters;

    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm parameters.
    type HashParameters;

    /// Hashing algorithm result.
    type Hashed;

    /// Proof generation algorithm parameters.
    type ProofParameters;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: Self::HashParameters,
    ) -> Result<Self::Hashed, Self::Error>;

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: &impl SignerProvider<M>,
        params: Self::ProofParameters,
    ) -> Result<Proof<Self, M>, Self::Error>;

    fn verify_proof(
        &self,
        data: Self::Hashed,
        verifier_provider: &impl VerifierProvider<M>,
        proof: &Proof<Self, M>,
    ) -> Result<ProofValidity, Self::Error>;
}

pub trait VerifiableCryptographicSuite<M>: CryptographicSuite<M> {
    /// Combination of transformation parameters and hash parameters that can
    /// be used to verify a credential.
    type VerificationParameters: VerificationParameters<
        Self::TransformationParameters,
        Self::HashParameters,
    >;
}

/// LD cryptographic suite.
pub trait LinkedDataCryptographicSuite<M, C>: CryptographicSuite<M> {
    /// Transformation algorithm.
    fn transform<T: LinkedDataCredential<C>>(
        &self,
        context: &mut C,
        data: &T,
        options: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error>;
}

/// Any LD cryptographic suite is a cryptographic suite working on LD documents.
impl<
        M,
        C,
        S: CryptographicSuite<M> + LinkedDataCryptographicSuite<M, C>,
        T: LinkedDataCredential<C>,
    > CryptographicSuiteInput<T, M, C> for S
{
    fn transform(
        &self,
        context: &mut C,
        data: &T,
        params: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error> {
        self.transform(context, data, params)
    }
}
