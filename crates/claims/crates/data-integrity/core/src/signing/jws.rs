use std::{borrow::Cow, marker::PhantomData};

use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_crypto::algorithm::{SignatureAlgorithmInstance, SignatureAlgorithmType};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{CompactJWSString, JWSSignature, JWS};
use ssi_verification_methods::{MessageSigner, VerifyBytes, VerifyBytesWithRecoveryJwk};

use crate::{
    suite::standard::{
        SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef,
};

use super::AlgorithmSelection;

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct JwsSignature {
    #[ld("sec:jws")]
    pub jws: CompactJWSString,
}

impl JwsSignature {
    pub fn new(jws: CompactJWSString) -> Self {
        Self { jws }
    }

    /// Decodes the signature for the given message.
    ///
    /// Returns the signing bytes, the signature bytes and the signature algorithm.
    pub fn decode(
        &self,
        message: &[u8],
    ) -> Result<(Vec<u8>, JWSSignature, Algorithm), ProofValidationError> {
        let JWS {
            header, signature, ..
        } = self
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        let signing_bytes = header.encode_signing_bytes(message);
        Ok((signing_bytes, signature, header.algorithm))
    }

    pub async fn sign_detached<A: SignatureAlgorithmType + Into<Algorithm>, S: MessageSigner<A>>(
        payload: &[u8],
        signer: S,
        key_id: Option<String>,
        algorithm_instance: A::Instance,
    ) -> Result<Self, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(algorithm_instance.algorithm().into(), key_id);
        let signing_bytes = header.encode_signing_bytes(payload);
        let signature = signer.sign(algorithm_instance, &signing_bytes).await?;
        let jws = ssi_jws::CompactJWSString::encode_detached(header, &signature);
        Ok(JwsSignature::new(jws))
    }
}

impl AsRef<str> for JwsSignature {
    fn as_ref(&self) -> &str {
        self.jws.as_str()
    }
}

impl super::AlterSignature for JwsSignature {
    fn alter(&mut self) {
        self.jws = CompactJWSString::from_string(format!("ff{}", self.jws)).unwrap();
    }
}

pub struct DetachedJwsSigning<A>(PhantomData<A>);

impl<A> SignatureAndVerificationAlgorithm for DetachedJwsSigning<A> {
    type Signature = JwsSignature;
}

impl<A, S, T> SignatureAlgorithm<S, T> for DetachedJwsSigning<A>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    A: SignatureAlgorithmType
        + AlgorithmSelection<S::VerificationMethod, S::ProofOptions>
        + Into<Algorithm>,
    T: MessageSigner<A>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(
            prepared_claims.as_ref(),
            signer,
            None,
            A::select_algorithm(verification_method, proof_configuration.options)?,
        )
        .await
    }
}

impl<A, S> VerificationAlgorithm<S> for DetachedJwsSigning<A>
where
    S: CryptographicSuite<Signature = JwsSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::VerificationMethod: VerifyBytes<A>,
    A: TryFrom<Algorithm>,
{
    fn verify(
        method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let JWS {
            header, signature, ..
        } = proof
            .signature
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let signing_bytes = header.encode_signing_bytes(prepared_claims.as_ref());

        let algorithm = header
            .algorithm
            .try_into()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        method.verify_bytes(algorithm, &signing_bytes, &signature)
    }
}

pub struct DetachedJwsRecoverySigning<A>(PhantomData<A>);

impl<A> SignatureAndVerificationAlgorithm for DetachedJwsRecoverySigning<A> {
    type Signature = JwsSignature;
}

impl<A, S, T> SignatureAlgorithm<S, T> for DetachedJwsRecoverySigning<A>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk,
    A: Clone + Into<Algorithm> + AlgorithmSelection<S::VerificationMethod, S::ProofOptions>,
    T: MessageSigner<A>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(
            prepared_claims.as_ref(),
            signer,
            proof_configuration.options.public_jwk().key_id.clone(),
            A::select_algorithm(verification_method, proof_configuration.options)?,
        )
        .await
    }
}

impl<A, S> VerificationAlgorithm<S> for DetachedJwsRecoverySigning<A>
where
    S: CryptographicSuite<Signature = JwsSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk,
    S::VerificationMethod: VerifyBytesWithRecoveryJwk<A>,
    A: TryFrom<ssi_jwk::Algorithm>,
{
    fn verify(
        verification_method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let JWS {
            header, signature, ..
        } = proof
            .signature
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let signing_bytes = header.encode_signing_bytes(prepared_claims.as_ref());

        let found_algorithm = header
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
