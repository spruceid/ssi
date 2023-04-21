//! Cryptographic suites.

mod ed25519_signature_2020;

use chrono::NaiveDateTime;
pub use ed25519_signature_2020::Ed25519Signature2020;
use rdf_types::Quad;
use treeldr_rust_prelude::iref::IriBuf;

use crate::{LinkedDataCredential, ProofValidity, SignerProvider, VerifierProvider};

pub struct TransformationOptions<T> {
    pub type_: T,
    pub cryptosuite: Option<String>,
}

pub struct ProofConfiguration<T, M = IriBuf, P = IriBuf> {
    pub type_: T,
    pub cryptosuite: Option<String>,
    pub created: NaiveDateTime,
    pub verification_method: M,
    pub proof_purpose: P,
}

impl<T, M, P> ProofConfiguration<T, M, P> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> Vec<Quad> {
        todo!("proof configuration quads")
    }
}

#[derive(Debug, Clone)]
pub struct ProofOptions<T, M = IriBuf, P = IriBuf> {
    pub type_: T,
    pub cryptosuite: Option<String>,
    pub created: NaiveDateTime,
    pub verification_method: M,
    pub proof_purpose: P,
}

impl<T, M, P> ProofOptions<T, M, P> {
    pub fn new(
        type_: T,
        cryptosuite: Option<String>,
        created: NaiveDateTime,
        verification_method: M,
        proof_purpose: P,
    ) -> Self {
        Self {
            type_,
            cryptosuite,
            created,
            verification_method,
            proof_purpose,
        }
    }
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
/// - `M`: verification method type. Represents the IRI to the verification
/// method. By default it is `IriBuf`, meaning that any IRI can be represented,
/// but some application may choose to restrict the supported methods.
/// - `P`: proof purpose type. Represents the IRI to the proof purpose. By
/// default it is `IriBuf`, meaning that any IRI can be represented, but some
/// application may choose to restrict the supported proof purposes.
// TODO: Is there an official set of proof purposes defined somewhere? In which
// case `P` might by superfluous.
pub struct DataIntegrityProof<T, M = IriBuf, P = IriBuf> {
    /// Proof type.
    pub type_: T,

    /// Cryptographic suite name.
    pub cryptosuite: Option<String>,

    /// Date and time of creation.
    pub created: NaiveDateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: P,

    /// Proof value.
    pub proof_value: String,
}

impl<T, M, P> DataIntegrityProof<T, M, P> {
    pub fn from_options(options: ProofOptions<T, M, P>, proof_value: String) -> Self {
        Self::new(
            options.type_,
            options.cryptosuite,
            options.created,
            options.verification_method,
            options.proof_purpose,
            proof_value,
        )
    }

    pub fn new(
        type_: T,
        cryptosuite: Option<String>,
        created: NaiveDateTime,
        verification_method: M,
        proof_purpose: P,
        proof_value: String,
    ) -> Self {
        Self {
            type_,
            cryptosuite,
            created,
            verification_method,
            proof_purpose,
            proof_value,
        }
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

/// Cryptographic suite.
///
/// The type parameter `T` is the type of documents on which the suite can be
/// applied.
pub trait CryptographicSuite<M> {
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

    /// Proof type.
    ///
    /// Return type of the proof generation algorithm.
    type Proof;

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
    ) -> Result<Self::Proof, Self::Error>;

    fn verify_proof(
        &self,
        data: Self::Hashed,
        verifier_provider: &impl VerifierProvider<M>,
        proof: &Self::Proof,
    ) -> Result<ProofValidity, Self::Error>;
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
