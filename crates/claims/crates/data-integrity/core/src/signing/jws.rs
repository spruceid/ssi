use std::{borrow::Cow, marker::PhantomData};

use ssi_claims_core::ProofValidationError;
use ssi_crypto::{AlgorithmInstance, SignatureError, Signer, Verifier};
use ssi_jwk::{Algorithm, VerifyingKey, JWK};
use ssi_jws::{DecodedJws, JwsPayload, JwsSignature, JwsString};
use ssi_verification_methods::VerificationMethod;

use crate::{
    suite::standard::{
        SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef,
};

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct DetachedJwsSignature {
    #[ld("sec:jws")]
    pub jws: JwsString,
}

impl DetachedJwsSignature {
    pub fn new(jws: impl Into<JwsString>) -> Self {
        Self { jws: jws.into() }
    }

    /// Decodes the signature for the given message.
    ///
    /// Returns the signing bytes, the signature bytes and the signature algorithm.
    pub fn decode(
        &self,
        message: &[u8],
    ) -> Result<(Vec<u8>, JwsSignature, Algorithm), ProofValidationError> {
        let DecodedJws {
            signing_bytes: detached_signing_bytes,
            signature,
        } = self
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        let signing_bytes = detached_signing_bytes.header.encode_signing_bytes(message);
        Ok((
            signing_bytes,
            signature,
            detached_signing_bytes.header.algorithm,
        ))
    }

    pub async fn sign_detached(
        signer: impl Signer,
        algorithm_instance: Option<AlgorithmInstance>,
        payload: &[u8],
    ) -> Result<Self, SignatureError> {
        payload.sign_detached(signer, algorithm_instance).await.map(Self::new)
    }
}

impl AsRef<str> for DetachedJwsSignature {
    fn as_ref(&self) -> &str {
        self.jws.as_str()
    }
}

impl super::AlterSignature for DetachedJwsSignature {
    fn alter(&mut self) {
        self.jws = JwsString::from_string(format!("ff{}", self.jws)).unwrap();
    }
}

pub struct DetachedJwsSigning;

impl SignatureAndVerificationAlgorithm for DetachedJwsSigning {
    type Signature = DetachedJwsSignature;
}

impl<S> SignatureAlgorithm<S> for DetachedJwsSigning
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>
{
    async fn sign(
        verification_method: &VerificationMethod,
        signer: impl Signer,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        DetachedJwsSignature::sign_detached(
            signer,
            None, // A::select_algorithm(verification_method, proof_configuration.options)?,
            prepared_claims.as_ref(),
        )
        .await
    }
}

impl<S> VerificationAlgorithm<S> for DetachedJwsSigning
where
    S: CryptographicSuite<Signature = DetachedJwsSignature>,
    S::PreparedClaims: AsRef<[u8]>
{
    fn verify(
        &self,
        verifier: impl VerifyingKey,
        method: &VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let DecodedJws {
            signing_bytes: detached_signing_bytes,
            signature,
        } = proof
            .signature
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let signing_bytes = detached_signing_bytes
            .header
            .encode_signing_bytes(prepared_claims.as_ref());

        let algorithm = detached_signing_bytes
            .header
            .algorithm
            .try_into()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        method.verify_bytes(algorithm, &signing_bytes, &signature)
    }
}

pub struct DetachedJwsRecoverySigning;

impl SignatureAndVerificationAlgorithm for DetachedJwsRecoverySigning {
    type Signature = DetachedJwsSignature;
}

impl<S> SignatureAlgorithm<S> for DetachedJwsRecoverySigning
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk
{
    async fn sign(
        verification_method: &VerificationMethod,
        signer: impl Signer,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        DetachedJwsSignature::sign_detached(
            signer,
            None, // A::select_algorithm(verification_method, proof_configuration.options)?,
            prepared_claims.as_ref(),
            // proof_configuration.options.public_jwk().key_id.clone(),
        )
        .await
    }
}

impl<S> VerificationAlgorithm<S> for DetachedJwsRecoverySigning
where
    S: CryptographicSuite<Signature = DetachedJwsSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk
{
    fn verify(
        &self,
        verifier: impl VerifyingKey,
        verification_method: &VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let DecodedJws {
            signing_bytes: detached_signing_bytes,
            signature,
        } = proof
            .signature
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let signing_bytes = detached_signing_bytes
            .header
            .encode_signing_bytes(prepared_claims.as_ref());

        let found_algorithm = detached_signing_bytes
            .header
            .algorithm
            .try_into()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        verification_method.verify_bytes_with_public_jwk(
            &proof.options.public_jwk(),
            found_algorithm,
            &signing_bytes,
            &signature,
        )
    }
}

pub trait RecoverPublicJwk {
    fn public_jwk(&self) -> Cow<JWK>;
}
