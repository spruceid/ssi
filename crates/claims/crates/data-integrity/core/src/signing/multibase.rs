use std::marker::PhantomData;

use multibase::Base;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_crypto::{key::metadata::infer_algorithm, AlgorithmInstance, SignatureError, Signer, Verifier};
use ssi_jwk::VerifyingKey;
use ssi_verification_methods::VerificationMethod;

use crate::{
    suite::standard::{
        SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef,
};

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
    pub fn new(signature: Box<[u8]>, base: Base) -> Self {
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

pub struct MultibaseSigning<B>(AlgorithmInstance, PhantomData<B>);

impl<B> SignatureAndVerificationAlgorithm for MultibaseSigning<B> {
    type Signature = MultibaseSignature;
}

impl<B, S> SignatureAlgorithm<S> for MultibaseSigning<B>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    B: StaticBase,
{
    async fn sign(
        verification_method: &VerificationMethod,
        signer: impl Signer,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        // let algorithm = A::select_algorithm(verification_method, proof_configuration.options)?;
        let (_, algorithm) = signer.key_metadata().into_id_and_algorithm(None)?;
        Ok(MultibaseSignature::new(
            signer.sign(algorithm, prepared_claims.as_ref()).await?,
            B::BASE,
        ))
    }
}

impl<B, S> VerificationAlgorithm<S> for MultibaseSigning<B>
where
    S: CryptographicSuite<Signature = MultibaseSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    B: StaticBase,
{
    fn verify(
        &self,
        verifier: impl VerifyingKey,
        verification_method: &VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        // let algorithm = verifier.key_metadata().into_id_and_algorithm(None);
        // let algorithm_instance = A::select_algorithm(verification_method, proof.options)?;
        let (_, signature_bytes) = proof.signature.decode()?; // Should we check the base?
        verifier.verify_bytes(
            self.0.clone(),
            prepared_claims.as_ref(),
            &signature_bytes,
        )
    }
}
