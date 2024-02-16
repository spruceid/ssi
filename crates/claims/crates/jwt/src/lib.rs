use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use ssi_core::one_or_many::OneOrMany;
use ssi_crypto::MessageSigner;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{CompactJWSString, Error, Header};

mod datatype;

pub use datatype::*;
use ssi_verification_methods::{
    ReferenceOrOwned, SignatureError, Signer, VerificationMethod, VerificationMethodResolver,
};

/// JSON Web Token.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[non_exhaustive]
pub struct JWTClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exp")]
    pub expiration_time: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iat")]
    pub issuance_date: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iss")]
    pub issuer: Option<StringOrURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nbf")]
    pub not_before: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sub")]
    pub subject: Option<StringOrURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "aud")]
    pub audience: Option<OneOrMany<StringOrURI>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vc")]
    pub verifiable_credential: Option<json_syntax::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vp")]
    pub verifiable_presentation: Option<json_syntax::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, serde_json::Value>>,
}

impl JWTClaims {
    pub async fn sign<M: VerificationMethod>(
        &self,
        algorithm: Algorithm,
        verification_method: &ReferenceOrOwned<M>,
        resolver: &impl VerificationMethodResolver<M>,
        signers: &impl Signer<M, Algorithm>,
    ) -> Result<CompactJWSString, SignatureError> {
        let verification_method = resolver
            .resolve_verification_method(
                None, // TODO issuer?
                Some(verification_method.borrowed()),
            )
            .await?;

        let signer = signers
            .for_method(verification_method.as_reference())
            .await
            .ok_or(SignatureError::MissingSigner)?;

        let payload = serde_json::to_string(self).unwrap();

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
