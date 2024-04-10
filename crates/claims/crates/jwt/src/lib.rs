use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::Serialize;

use ssi_core::one_or_many::OneOrMany;
use ssi_crypto::MessageSigner;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{CompactJWSString, Error, Header};

mod claims;
mod datatype;
mod de;

pub use claims::*;
pub use datatype::*;
use ssi_verification_methods::{
    MaybeJwkVerificationMethod, ReferenceOrOwnedRef, SignatureError, Signer,
    VerificationMethodResolver,
};

/// JSON Web Token claims.
#[derive(Debug, Serialize, Clone, Default)]
#[non_exhaustive]
pub struct JWTClaims<PrivateClaims = AnyClaims> {
    /// Issuer (`iss`) claim.
    ///
    /// Principal that issued the JWT. The processing of this claim is generally
    /// application specific.
    #[serde(rename = "iss")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<StringOrURI>,

    /// Subject (`sub`) claim.
    ///
    /// Principal that is the subject of the JWT. The claims in a JWT are
    /// normally statements about the subject. The subject value MUST either be
    /// scoped to be locally unique in the context of the issuer or be globally
    /// unique.
    ///
    /// The processing of this claim is generally application specific.
    #[serde(rename = "sub")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<StringOrURI>,

    /// Audience (`aud`) claim.
    ///
    /// Recipients that the JWT is intended for. Each principal intended to
    /// process the JWT MUST identify itself with a value in the audience claim.
    /// If the principal processing the claim does not identify itself with a
    /// value in the `aud` claim when this claim is present, then the JWT MUST
    /// be rejected.
    #[serde(rename = "aud")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<OneOrMany<StringOrURI>>,

    /// Expiration Time (`exp`) claim.
    ///
    /// Expiration time on or after which the JWT MUST NOT be accepted for
    /// processing. The processing of the `exp` claim requires that the current
    /// date/time MUST be before the expiration date/time listed in the `exp`
    /// claim.
    #[serde(rename = "exp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<NumericDate>,

    /// Not Before (`nbf`) claim.
    ///
    /// Time before which the JWT MUST NOT be accepted for processing. The
    /// processing of the `nbf` claim requires that the current date/time MUST
    /// be after or equal to the not-before date/time listed in the "nbf" claim.
    /// Implementers MAY provide for some small leeway, usually no more than a
    /// few minutes, to account for clock skew.
    #[serde(rename = "nbf")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NumericDate>,

    /// Issued At (`iat`) claim.
    ///
    /// Time at which the JWT was issued. This claim can be used to determine
    /// the age of the JWT.
    #[serde(rename = "iat")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<NumericDate>,

    /// JWT ID (`jti`) claim.
    ///
    /// Unique identifier for the JWT. The identifier value MUST be assigned in
    /// a manner that ensures that there is a negligible probability that the
    /// same value will be accidentally assigned to a different data object; if
    /// the application uses multiple issuers, collisions MUST be prevented
    /// among values produced by different issuers as well.
    ///
    /// The "jti" claim can be used to prevent the JWT from being replayed.
    #[serde(rename = "jti")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    /// Other registered claims.
    #[serde(flatten)]
    pub registered_claims: RegisteredClaims,

    /// Private, non-registered claims.
    #[serde(flatten)]
    pub private_claims: PrivateClaims
}

impl<P> JWTClaims<P> {
    pub fn from_private_claims(claims: P) -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            expiration_time: None,
            not_before: None,
            issuance_date: None,
            jwt_id: None,
            registered_claims: RegisteredClaims::default(),
            private_claims: claims
        }
    }
}

impl JWTClaims<()> {
    pub fn with_private_claims<P>(self, claims: P) -> JWTClaims<P> {
        JWTClaims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expiration_time: self.expiration_time,
            not_before: self.not_before,
            issuance_date: self.issuance_date,
            jwt_id: self.jwt_id,
            registered_claims: self.registered_claims,
            private_claims: claims
        }
    }
}

impl<P: Serialize> JWTClaims<P> {
    /// Sign the claims and return a JWT.
    pub async fn sign<'m, M: 'm + MaybeJwkVerificationMethod>(
        &self,
        verification_method: impl Into<ReferenceOrOwnedRef<'m, M>>,
        resolver: &impl VerificationMethodResolver<M>,
        signers: &impl Signer<M, Algorithm>,
    ) -> Result<CompactJWSString, SignatureError> {
        sign_claims(self, verification_method, resolver, signers).await
    }
}

/// Any set of claims.
pub type AnyClaims = HashMap<String, serde_json::Value>;

pub trait ClaimSet {
    fn get<'a>(&self, claim: ClaimKind<&str>) -> Option<&Claim>;
}

/// Sign the claims and return a JWT.
pub async fn sign_claims<'m, M: 'm + MaybeJwkVerificationMethod>(
    claims: &impl Serialize,
    verification_method: impl Into<ReferenceOrOwnedRef<'m, M>>,
    resolver: &impl VerificationMethodResolver<M>,
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
