use crate::{verify_bytes, DecodedJWS, DecodedSigningBytes, Error};
use iref::Iri;
use ssi_claims_core::{
    ExtractProof, PrepareWith, Proof, ProofValidity, Validate, VerifiableClaims, VerifyClaimsWith,
};
use ssi_jwk::{Algorithm, JWK};
use ssi_verification_methods_core::{
    MaybeJwkVerificationMethod, VerificationError, VerificationMethodResolver,
};
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
    async fn fetch_jwk(&self, key_id: Option<&str>) -> Result<Cow<JWK>, VerificationError>;

    #[allow(async_fn_in_trait)]
    async fn verify(
        &self,
        signing_bytes: &[u8],
        signature: &[u8],
        key_id: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<ProofValidity, VerificationError> {
        let key = self.fetch_jwk(key_id).await?;
        match verify_bytes(algorithm, signing_bytes, &key, signature) {
            Ok(()) => Ok(ProofValidity::Valid),
            Err(Error::InvalidSignature) => Ok(ProofValidity::Invalid),
            Err(_) => Err(VerificationError::InvalidSignature),
        }
    }
}

impl<V: VerificationMethodResolver> JWSVerifier for V
where
    V::Method: MaybeJwkVerificationMethod,
{
    async fn fetch_jwk(&self, key_id: Option<&str>) -> Result<Cow<JWK>, VerificationError> {
        use ssi_verification_methods_core::{
            ReferenceOrOwnedRef, VerificationMethodResolutionError,
        };
        let vm = match key_id {
            Some(id) => match Iri::new(id) {
                Ok(iri) => Some(ReferenceOrOwnedRef::Reference(iri)),
                Err(_) => {
                    return Err(VerificationError::Resolution(
                        VerificationMethodResolutionError::MissingVerificationMethod,
                    ))
                }
            },
            None => None,
        };

        self.resolve_verification_method(None, vm)
            .await?
            .try_to_jwk()
            .map(Cow::into_owned)
            .map(Cow::Owned)
            .ok_or(VerificationError::Resolution(
                VerificationMethodResolutionError::MissingVerificationMethod,
            ))
    }
}

/// Signing bytes are valid if the decoded payload is valid.
impl<T: Validate> Validate for DecodedSigningBytes<T> {
    fn is_valid(&self) -> bool {
        self.payload.is_valid()
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
    type Error = std::convert::Infallible;

    async fn prepare_with(
        self,
        _claims: &DecodedSigningBytes<T>,
        _environment: &mut (),
    ) -> Result<Self::Prepared, Self::Error> {
        Ok(self)
    }
}

impl<T, V: JWSVerifier> VerifyClaimsWith<DecodedSigningBytes<T>, V> for Signature {
    type Error = VerificationError;

    async fn verify_claims_with<'a>(
        &'a self,
        claims: &'a DecodedSigningBytes<T>,
        verifier: &'a V,
    ) -> Result<ProofValidity, Self::Error> {
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
