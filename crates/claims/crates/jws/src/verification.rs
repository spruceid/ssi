use crate::{verify_bytes, DecodedJWS, DecodedSigningBytes, Error, Header};
use ssi_claims_core::{
    ClaimsValidity, DefaultVerificationEnvironment, InvalidProof, ProofValidationError,
    ProofValidity, Validate, ValidateProof, VerifiableClaims,
};
use ssi_jwk::{Algorithm, JWK};
use std::{
    borrow::{Borrow, Cow},
    ops::Deref,
};

pub trait ValidateJWSHeader<E> {
    fn validate_jws_header(&self, env: &E, header: &Header) -> ClaimsValidity;
}

impl<E> ValidateJWSHeader<E> for [u8] {
    fn validate_jws_header(&self, _env: &E, _header: &Header) -> ClaimsValidity {
        Ok(())
    }
}

impl<'a, E, T: ?Sized + ToOwned + ValidateJWSHeader<E>> ValidateJWSHeader<E> for Cow<'a, T> {
    fn validate_jws_header(&self, env: &E, header: &Header) -> ClaimsValidity {
        self.as_ref().validate_jws_header(env, header)
    }
}

impl<E, T: Validate<E, JWSSignature> + ValidateJWSHeader<E>> Validate<E, JWSSignature>
    for DecodedSigningBytes<T>
{
    fn validate(&self, env: &E, proof: &JWSSignature) -> ClaimsValidity {
        self.payload.validate_jws_header(env, &self.header)?;
        self.payload.validate(env, proof)
    }
}

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

impl<'a, T: JWSVerifier> JWSVerifier for &'a T {
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError> {
        T::fetch_public_jwk(*self, key_id).await
    }

    async fn verify(
        &self,
        signing_bytes: &[u8],
        signature: &[u8],
        key_id: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<ProofValidity, ProofValidationError> {
        T::verify(*self, signing_bytes, signature, key_id, algorithm).await
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWSSignature(Vec<u8>);

impl JWSSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for JWSSignature {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<JWSSignature> for Vec<u8> {
    fn from(value: JWSSignature) -> Self {
        value.into_bytes()
    }
}

impl Deref for JWSSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for JWSSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for JWSSignature {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl<T> VerifiableClaims for DecodedJWS<T> {
    type Claims = DecodedSigningBytes<T>;
    type Proof = JWSSignature;

    fn claims(&self) -> &Self::Claims {
        &self.signing_bytes
    }

    fn proof(&self) -> &Self::Proof {
        &self.signature
    }
}

impl<T: DefaultVerificationEnvironment> DefaultVerificationEnvironment for DecodedJWS<T> {
    type Environment = ();
}

impl<T, E, V> ValidateProof<DecodedSigningBytes<T>, E, V> for JWSSignature
where
    V: JWSVerifier,
{
    async fn validate_proof<'a>(
        &'a self,
        _environment: &'a E,
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
