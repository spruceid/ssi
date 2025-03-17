use serde::{Deserialize, Serialize};
use ssi_claims_core::Parameters;
use ssi_crypto::{key::KeyMetadata, Error, SignatureVerification, Signer};
use ssi_jwk::VerifyingKey;

mod sd;
pub use sd::*;

use crate::proof::{Proof, ProofRef};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CryptographicSuiteType {
    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "cryptosuite")]
    pub crypto_suite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CryptographicSuiteTypeRef<'a> {
    #[serde(rename = "type")]
    pub r#type: &'a str,

    #[serde(rename = "cryptosuite")]
    pub crypto_suite: Option<&'a str>,
}

/// Cryptographic suite.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites>
pub trait CryptographicSuite: Sized {
    fn from_type(r#type: CryptographicSuiteTypeRef) -> Option<Self>;

    fn r#type(&self) -> CryptographicSuiteTypeRef;

    fn strip_proof_value(proof: &mut ProofRef<Self>) {
        proof.proof_value = None;
    }
}

pub trait StaticCryptographicSuite: Default {
    const CRYPTO_SUITE: &str;
}

impl<T: StaticCryptographicSuite> CryptographicSuite for T {
    fn from_type(r#type: CryptographicSuiteTypeRef) -> Option<Self> {
        if r#type.r#type == "DataIntegrityProof" && r#type.crypto_suite == Some(Self::CRYPTO_SUITE)
        {
            Some(Self::default())
        } else {
            None
        }
    }

    fn r#type(&self) -> CryptographicSuiteTypeRef {
        CryptographicSuiteTypeRef {
            r#type: "DataIntegrityProof",
            crypto_suite: Some(Self::CRYPTO_SUITE),
        }
    }
}

pub trait CryptographicSuiteFor<T>: CryptographicSuite {
    /// How prepared claims are stored.
    ///
    /// This is the output of the hashing algorithm.
    type PreparedClaims;

    /// Prepare the claims for signature or verification.
    #[allow(async_fn_in_trait)]
    async fn prepare(
        claims: &T,
        configuration: ProofRef<Self>,
        key_metadata: KeyMetadata,
        params: &Parameters,
    ) -> Result<Self::PreparedClaims, Error>;

    /// Prepare the claims for signature or verification.
    #[allow(async_fn_in_trait)]
    async fn generate_proof(
        issuer: impl Signer,
        claims: Self::PreparedClaims,
        configuration: Proof<Self>,
        params: &Parameters,
    ) -> Result<Proof<Self>, Error>;

    /// Prepare the claims for signature or verification.
    #[allow(async_fn_in_trait)]
    async fn verify_proof(
        verifier: impl VerifyingKey,
        claims: Self::PreparedClaims,
        proof: ProofRef<Self>,
        params: &Parameters,
    ) -> Result<SignatureVerification, Error>;
}
