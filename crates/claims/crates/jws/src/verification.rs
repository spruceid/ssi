use crate::{DecodedJws, DecodedSigningBytes, Header};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ssi_claims_core::{
    ClaimsValidity, ProofValidationError, ProofValidity, ValidateClaims, ValidateProof,
    VerifiableClaims, VerificationParameters,
};
use ssi_crypto::Verifier;
use std::{
    borrow::{Borrow, Cow},
    ops::Deref,
};

pub trait ValidateJwsHeader {
    fn validate_jws_header(
        &self,
        _env: &VerificationParameters,
        _header: &Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl ValidateJwsHeader for [u8] {}

impl<'a, T: ?Sized + ToOwned + ValidateJwsHeader> ValidateJwsHeader for Cow<'a, T> {
    fn validate_jws_header(&self, env: &VerificationParameters, header: &Header) -> ClaimsValidity {
        self.as_ref().validate_jws_header(env, header)
    }
}

impl<'a, T: ValidateClaims<JwsSignature> + ValidateJwsHeader> ValidateClaims<JwsSignature>
    for DecodedSigningBytes<'a, T>
{
    fn validate_claims(
        &self,
        env: &VerificationParameters,
        signature: &JwsSignature,
    ) -> ClaimsValidity {
        self.payload.validate_jws_header(env, &self.header)?;
        self.payload.validate_claims(env, signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsSignature(Box<[u8]>);

impl JwsSignature {
    pub fn new(bytes: Box<[u8]>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }
}

impl From<Vec<u8>> for JwsSignature {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for JwsSignature {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl From<JwsSignature> for Box<[u8]> {
    fn from(value: JwsSignature) -> Self {
        value.into_bytes()
    }
}

impl Deref for JwsSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for JwsSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for JwsSignature {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a, T> VerifiableClaims for DecodedJws<'a, T> {
    type Claims = DecodedSigningBytes<'a, T>;
    type Proof = JwsSignature;

    fn claims(&self) -> &Self::Claims {
        &self.signing_bytes
    }

    fn proof(&self) -> &Self::Proof {
        &self.signature
    }
}

impl<'b, T> ValidateProof<DecodedSigningBytes<'b, T>> for JwsSignature {
    async fn validate_proof<'a>(
        &'a self,
        verifier: impl Verifier,
        _params: &'a VerificationParameters,
        claims: &'a DecodedSigningBytes<'b, T>,
    ) -> Result<ProofValidity, ProofValidationError> {
        Ok(verifier
            .verify_bytes(
                claims.header.key_id.as_ref().map(String::as_bytes),
                Some(claims.header.algorithm.into()),
                &claims.bytes,
                &self.0,
            )
            .await?
            .map_err(Into::into))
    }
}
