use crate::{verify_bytes, DecodedJWS, DecodedSigningBytes, Error, Header};
use ssi_claims_core::{
    ClaimsValidity, InvalidProof, ProofValidationError, ProofValidity, ResolverProvider,
    ValidateClaims, ValidateProof, VerifiableClaims,
};
use ssi_jwk::JWKResolver;
use std::{
    borrow::{Borrow, Cow},
    ops::Deref,
};

pub trait ValidateJWSHeader<E> {
    fn validate_jws_header(&self, _env: &E, _header: &Header) -> ClaimsValidity {
        Ok(())
    }
}

impl<E> ValidateJWSHeader<E> for [u8] {}

impl<'a, E, T: ?Sized + ToOwned + ValidateJWSHeader<E>> ValidateJWSHeader<E> for Cow<'a, T> {
    fn validate_jws_header(&self, env: &E, header: &Header) -> ClaimsValidity {
        self.as_ref().validate_jws_header(env, header)
    }
}

impl<'a, E, T: ValidateClaims<E, JWSSignature> + ValidateJWSHeader<E>>
    ValidateClaims<E, JWSSignature> for DecodedSigningBytes<'a, T>
{
    fn validate_claims(&self, env: &E, signature: &JWSSignature) -> ClaimsValidity {
        self.payload.validate_jws_header(env, &self.header)?;
        self.payload.validate_claims(env, signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWSSignature(Vec<u8>);

impl JWSSignature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

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
        self.as_bytes()
    }
}

impl AsRef<[u8]> for JWSSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for JWSSignature {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a, T> VerifiableClaims for DecodedJWS<'a, T> {
    type Claims = DecodedSigningBytes<'a, T>;
    type Proof = JWSSignature;

    fn claims(&self) -> &Self::Claims {
        &self.signing_bytes
    }

    fn proof(&self) -> &Self::Proof {
        &self.signature
    }
}

impl<'b, V, T> ValidateProof<V, DecodedSigningBytes<'b, T>> for JWSSignature
where
    V: ResolverProvider,
    V::Resolver: JWKResolver,
{
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a DecodedSigningBytes<'b, T>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let key = verifier
            .resolver()
            .fetch_public_jwk(claims.header.key_id.as_deref())
            .await?;
        match verify_bytes(claims.header.algorithm, &claims.bytes, &key, &self.0) {
            Ok(()) => Ok(Ok(())),
            Err(Error::InvalidSignature) => Ok(Err(InvalidProof::Signature)),
            Err(_) => Err(ProofValidationError::InvalidSignature),
        }
    }
}
