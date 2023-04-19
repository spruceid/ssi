//! Cryptographic suites.

mod ed25519_signature_2020;

use chrono::NaiveDateTime;
pub use ed25519_signature_2020::Ed25519Signature2020;
use iref::Iri;
use rdf_types::Quad;
use treeldr_rust_prelude::iref::IriBuf;

use crate::LinkedDataCredential;

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
        todo!()
    }
}

pub struct ProofOptions<T, M = IriBuf, P = IriBuf> {
    pub type_: T,
    pub cryptosuite: Option<String>,
    pub created: NaiveDateTime,
    pub verification_method: M,
    pub proof_purpose: P,
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
/// - `M`: verification method type. Represents the IRI to the verification
/// method.
/// - `P`: proof purpose.
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

/// Error raised when a proof verification fails.
pub struct InvalidProof;

pub enum Algorithm {
    /// Edwards-Curve Digital Signature Algorithm ([RFC8032]).
    ///
    /// [RFC8032]: <https://www.rfc-editor.org/rfc/rfc8032>
    EdDSA,
}

pub trait Signer {
    fn sign(&self, algorithm: Algorithm, bytes: &[u8]) -> Vec<u8>;
}

pub trait SignerProvider {
    type Signer: Signer;

    fn get_signer(&self, method: Iri) -> Self::Signer;
}

/// Verifier.
pub trait Verifier {
    /// Verify the given `signed_bytes`, signed using the given `algorithm`,
    /// against the input `unsigned_bytes`.
    fn verify(&self, algorithm: Algorithm, unsigned_bytes: &[u8], signed_bytes: &[u8]) -> bool;
}

/// Verifier provider.
///
/// The implementor is in charge of retrieve verification methods as described
/// in <https://w3c.github.io/vc-data-integrity/#retrieve-verification-method>.
pub trait VerifierProvider {
    /// Verifier type.
    type Verifier: Verifier;

    /// Retrieve the verifier identified by the given verification `method`.
    fn get_verifier(&self, method: Iri) -> Self::Verifier;
}

/// Cryptographic suite.
///
/// The type parameter `T` is the type of documents on which the suite can be
/// applied.
pub trait CryptographicSuite<T> {
    /// Execution context.
    type Context;

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

    /// Transformation algorithm.
    fn transform(
        &self,
        context: &mut Self::Context,
        data: T,
        params: Self::TransformationParameters,
    ) -> Self::Transformed;

    /// Hashing algorithm.
    fn hash(&self, data: Self::Transformed, params: Self::HashParameters) -> Self::Hashed;

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: impl SignerProvider,
        params: Self::ProofParameters,
    ) -> Self::Proof;

    fn verify_proof(
        &self,
        verifier_provider: impl VerifierProvider,
        data: Self::Hashed,
        proof: &Self::Proof,
    ) -> Result<(), InvalidProof>;
}

/// LD cryptographic suite.
pub trait LinkedDataCryptographicSuite {
    type TransformationParameters;
    type Transformed;

    type HashParameters;
    type Hashed;

    type ProofParameters;
    type Proof;

    /// Transformation algorithm.
    fn transform<C: LinkedDataCredential>(
        &self,
        context: &mut C::Context,
        data: C,
        options: Self::TransformationParameters,
    ) -> Self::Transformed;

    /// Hashing algorithm.
    fn hash(&self, data: Self::Transformed, options: Self::HashParameters) -> Self::Hashed;

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: impl SignerProvider,
        options: Self::ProofParameters,
    ) -> Self::Proof;

    fn verify_proof(
        &self,
        verifier_provider: impl VerifierProvider,
        data: Self::Hashed,
        proof: &Self::Proof,
    ) -> Result<(), InvalidProof>;
}

/// Any LD cryptographic suite is a cryptographic suite working on LD documents.
impl<S: LinkedDataCryptographicSuite, T: LinkedDataCredential> CryptographicSuite<T> for S {
    type Context = T::Context;

    type TransformationParameters = S::TransformationParameters;
    type Transformed = S::Transformed;

    type HashParameters = S::HashParameters;
    type Hashed = S::Hashed;

    type ProofParameters = S::ProofParameters;
    type Proof = S::Proof;

    fn transform(
        &self,
        context: &mut Self::Context,
        data: T,
        params: Self::TransformationParameters,
    ) -> Self::Transformed {
        self.transform(context, data, params)
    }

    /// Hashing algorithm.
    fn hash(&self, data: Self::Transformed, options: Self::HashParameters) -> Self::Hashed {
        self.hash(data, options)
    }

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: impl SignerProvider,
        params: Self::ProofParameters,
    ) -> Self::Proof {
        self.generate_proof(data, signer_provider, params)
    }

    fn verify_proof(
        &self,
        verifier_provider: impl VerifierProvider,
        data: Self::Hashed,
        proof: &Self::Proof,
    ) -> Result<(), InvalidProof> {
        self.verify_proof(verifier_provider, data, proof)
    }
}
