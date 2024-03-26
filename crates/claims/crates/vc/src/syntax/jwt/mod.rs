use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi_jwt::JWTClaims;

mod decode;
mod encode;

pub use decode::*;
pub use encode::*;

/// Public claims related to Verifiable Credentials.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VCPublicClaims {
    /// Verifiable Credential as specified in the W3C Recommendation.
    #[serde(rename = "vc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<json_syntax::Value>,

    /// Verifiable Presentation as specified in the W3C Recommendation.
    #[serde(rename = "vp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_presentation: Option<json_syntax::Value>,
}

impl<P: DeserializeOwned> super::JsonVerifiableCredential<P> {
    /// Decodes a verifiable credential from the claims of a JWT following the
    /// standard [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn from_jwt_claims(jwt: JWTClaims<VCPublicClaims>) -> Result<Self, JwtVcDecodeError> {
        decode_jwt_vc_claims(jwt)
    }
}

impl<P: Serialize> super::JsonVerifiableCredential<P> {
    /// Encodes this verifiable credential into the claims of a JWT following
    /// the standard [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn to_jwt_claims(&self) -> Result<JWTClaims<VCPublicClaims>, JwtVcEncodeError> {
        encode_jwt_vc_claims(self)
    }
}

impl super::SpecializedJsonCredential {
    /// Encodes this credential into the claims of a JWT following the standard
    /// [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn to_jwt_claims(&self) -> Result<JWTClaims<VCPublicClaims>, JwtVcEncodeError> {
        encode_jwt_vc_claims(self)
    }
}

impl<C: DeserializeOwned, P: DeserializeOwned> super::JsonVerifiablePresentation<C, P> {
    /// Decodes a verifiable presentation from the claims of a JWT following the
    /// standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn from_jwt_claims(jwt: JWTClaims<VCPublicClaims>) -> Result<Self, JwtVpDecodeError> {
        decode_jwt_vp_claims(jwt)
    }
}

impl<C: Serialize, P: Serialize> super::JsonVerifiablePresentation<C, P> {
    /// Encodes this verifiable presentation into the claims of a JWT following
    /// the standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn to_jwt_claims(&self) -> Result<JWTClaims<VCPublicClaims>, JwtVpEncodeError> {
        encode_jwt_vp_claims(self)
    }
}

impl<C: Serialize> super::JsonPresentation<C> {
    /// Encodes this presentation into the claims of a JWT following the
    /// standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    pub fn to_jwt_claims(&self) -> Result<JWTClaims<VCPublicClaims>, JwtVpEncodeError> {
        encode_jwt_vp_claims(self)
    }
}
