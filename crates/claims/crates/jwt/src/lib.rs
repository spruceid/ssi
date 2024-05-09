use serde::de::DeserializeOwned;
use serde::Serialize;

use ssi_crypto::MessageSigner;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{CompactJWSString, Error, Header};

mod claims;
mod datatype;

pub use claims::*;
pub use datatype::*;
use ssi_verification_methods::{
    MaybeJwkVerificationMethod, ReferenceOrOwnedRef, SignatureError, Signer,
    VerificationMethodResolver,
};

/// Sign the claims and return a JWT.
pub async fn sign_claims<'m, M: 'm + MaybeJwkVerificationMethod>(
    claims: &impl Serialize,
    verification_method: impl Into<ReferenceOrOwnedRef<'m, M>>,
    resolver: &impl VerificationMethodResolver<Method = M>,
    signers: &impl Signer<M, Algorithm>,
) -> Result<CompactJWSString, SignatureError> {
    let verification_method = resolver
        .resolve_verification_method(
            None, // TODO issuer?
            Some(verification_method.into()),
        )
        .await?;

    let jwk = verification_method
        .try_to_jwk()
        .ok_or(SignatureError::MissingAlgorithm)?;
    let algorithm = jwk
        .get_algorithm()
        .ok_or(SignatureError::MissingAlgorithm)?;

    let signer = signers
        .for_method(verification_method.as_reference())
        .await
        .ok_or(SignatureError::MissingSigner)?;

    let payload = serde_json::to_string(claims).unwrap();

    let header = Header {
        algorithm,
        key_id: Some(verification_method.id().to_owned().into()),
        type_: Some("JWT".to_string()),
        ..Default::default()
    };

    let signing_bytes = header.encode_signing_bytes(payload.as_bytes());
    let signature = signer.sign(algorithm, (), &signing_bytes).await?;

    Ok(
        CompactJWSString::encode_from_signing_bytes_and_signature(signing_bytes, &signature)
            .unwrap(),
    )
}

// RFC 7519 - JSON Web Token (JWT)

pub fn encode_sign<Claims: Serialize>(
    algorithm: Algorithm,
    claims: &Claims,
    key: &JWK,
) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        type_: Some("JWT".to_string()),
        ..Default::default()
    };
    ssi_jws::encode_sign_custom_header(&payload, key, &header)
}

pub fn encode_unsigned<Claims: Serialize>(claims: &Claims) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    ssi_jws::encode_unsigned(&payload)
}

pub fn decode_verify<Claims: DeserializeOwned>(jwt: &str, key: &JWK) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_verify(jwt, key)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}

// for vc-test-suite
pub fn decode_unverified<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_unverified(jwt)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}
