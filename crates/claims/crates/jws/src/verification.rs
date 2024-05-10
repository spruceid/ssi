use crate::{verify_bytes, DecodedJWS, DecodedSigningBytes, Error};
use ssi_claims_core::{
    ExtractProof, InvalidProof, PrepareWith, Proof, ProofPreparationError, ProofValidationError,
    ProofValidity, Validate, ValidateProof, VerifiableClaims,
};
use ssi_jwk::{Algorithm, JWK};
use std::borrow::Cow;

/// JWS verifier.
///
/// Any type that can fetch a JWK using the `kid` parameter of a JWS JOSE
/// header.
pub trait JWSVerifier {
    /// Fetches a JWK by id.
    ///
    /// The key identifier is optional since the key may be known in advance.
    #[allow(async_fn_in_trait)]
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError>;

    #[allow(async_fn_in_trait)]
    async fn verify(
        &self,
        signing_bytes: &[u8],
        signature: &[u8],
        key_id: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<ProofValidity, ProofValidationError> {
        let key = self.fetch_public_jwk(key_id).await?;
        match verify_bytes(algorithm, signing_bytes, &key, signature) {
            Ok(()) => Ok(Ok(())),
            Err(Error::InvalidSignature) => Ok(Err(InvalidProof::Signature)),
            Err(_) => Err(ProofValidationError::InvalidSignature),
        }
    }
}

impl JWSVerifier for JWK {
    async fn fetch_public_jwk(
        &self,
        _key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError> {
        Ok(Cow::Borrowed(self))
    }
}

/// Signing bytes are valid if the decoded payload is valid.
impl<E, T: Validate<E>> Validate<E> for DecodedSigningBytes<T> {
    fn validate(&self, env: &E) -> ssi_claims_core::ClaimsValidity {
        self.payload.validate(env)
    }
}

pub struct Signature(Vec<u8>);

impl<T> VerifiableClaims for DecodedJWS<T> {
    type Proof = Signature;
}

impl<T> ExtractProof for DecodedJWS<T> {
    type Proofless = DecodedSigningBytes<T>;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof) {
        let signing_bytes = DecodedSigningBytes {
            bytes: self.signing_bytes,
            header: self.decoded.header,
            payload: self.decoded.payload,
        };

        let signature = Signature(self.decoded.signature);

        (signing_bytes, signature)
    }
}

impl Proof for Signature {
    type Prepared = Self;
}

impl<T> PrepareWith<DecodedSigningBytes<T>> for Signature {
    async fn prepare_with(
        self,
        _claims: &DecodedSigningBytes<T>,
        _environment: &mut (),
    ) -> Result<Self::Prepared, ProofPreparationError> {
        Ok(self)
    }
}

impl<T, V: JWSVerifier> ValidateProof<DecodedSigningBytes<T>, V> for Signature {
    async fn validate_proof<'a>(
        &'a self,
        claims: &'a DecodedSigningBytes<T>,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        verifier
            .verify(
                &claims.bytes,
                &self.0,
                claims.header.key_id.as_deref(),
                claims.header.algorithm,
            )
            .await
    }
}