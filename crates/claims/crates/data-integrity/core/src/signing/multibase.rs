use std::marker::PhantomData;

use multibase::Base;
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_crypto::algorithm::SignatureAlgorithmInstance;
use ssi_verification_methods::{MessageSigner, VerifyBytes};

use crate::{
    suite::standard::{
        SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef,
};

use super::AlgorithmSelection;

/// Common signature format where the proof value is multibase-encoded.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct MultibaseSignature {
    /// Multibase encoded signature.
    #[serde(rename = "proofValue")]
    #[ld("sec:proofValue")]
    pub proof_value: String,
}

impl MultibaseSignature {
    pub fn new(signature: Vec<u8>, base: Base) -> Self {
        Self {
            proof_value: multibase::encode(base, signature),
        }
    }

    pub fn new_base58btc(signature: Vec<u8>) -> Self {
        Self {
            proof_value: multibase::encode(Base::Base58Btc, signature),
        }
    }

    pub fn decode(&self) -> Result<(Base, Vec<u8>), ProofValidationError> {
        multibase::decode(&self.proof_value).map_err(|_| ProofValidationError::InvalidSignature)
    }
}

impl AsRef<str> for MultibaseSignature {
    fn as_ref(&self) -> &str {
        &self.proof_value
    }
}

impl super::AlterSignature for MultibaseSignature {
    fn alter(&mut self) {
        self.proof_value.push_str("ff")
    }
}

pub trait StaticBase {
    const BASE: Base;
}

pub struct Base58Btc;

impl StaticBase for Base58Btc {
    const BASE: Base = Base::Base58Btc;
}

pub struct MultibaseSigning<A, B>(PhantomData<(A, B)>);

impl<A, B> SignatureAndVerificationAlgorithm for MultibaseSigning<A, B> {
    type Signature = MultibaseSignature;
}

impl<A, B, S, T> SignatureAlgorithm<S, T> for MultibaseSigning<A, B>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    A: AlgorithmSelection<S::VerificationMethod, S::ProofOptions>,
    B: StaticBase,
    T: MessageSigner<A>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        let algorithm = A::select_algorithm(verification_method, proof_configuration.options)?;

        Ok(MultibaseSignature::new(
            signer.sign(algorithm, prepared_claims.as_ref()).await?,
            B::BASE,
        ))
    }
}

impl<A, B, S> VerificationAlgorithm<S> for MultibaseSigning<A, B>
where
    S: CryptographicSuite<Signature = MultibaseSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::VerificationMethod: VerifyBytes<A>,
    A: AlgorithmSelection<S::VerificationMethod, S::ProofOptions>,
    B: StaticBase,
{
    fn verify(
        verification_method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let algorithm_instance = A::select_algorithm(verification_method, proof.options)?;

        let (_, signature_bytes) = proof.signature.decode()?; // Should we check the base?
        verification_method.verify_bytes(
            algorithm_instance.algorithm(),
            prepared_claims.as_ref(),
            &signature_bytes,
        )
    }
}
