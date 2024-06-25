use serde::{de::DeserializeOwned, Serialize};
use ssi_data_integrity::{CryptographicSuite, DataIntegrity};
use ssi_jwt::{ClaimSet, RegisteredClaims};

mod decode;
mod encode;

pub use decode::*;
pub use encode::*;

pub trait FromJwtClaims: Sized {
    type Error;

    fn from_jwt_claims(jwt: impl ClaimSet) -> Result<Self, Self::Error>;
}

pub trait ToJwtClaims {
    type Error;

    fn to_jwt_claims(&self) -> Result<RegisteredClaims, Self::Error>;
}

impl<S> FromJwtClaims for DataIntegrity<super::SpecializedJsonCredential, S>
where
    S: CryptographicSuite + TryFrom<ssi_data_integrity::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::ProofOptions: DeserializeOwned,
    S::Signature: DeserializeOwned,
{
    type Error = JwtVcDecodeError;

    /// Decodes a verifiable credential from the claims of a JWT following the
    /// standard [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn from_jwt_claims(jwt: impl ClaimSet) -> Result<Self, JwtVcDecodeError> {
        decode_jwt_vc_claims(jwt)
    }
}

impl<S: CryptographicSuite> ToJwtClaims for DataIntegrity<super::SpecializedJsonCredential, S>
where
    S::VerificationMethod: Serialize,
    S::ProofOptions: Serialize,
    S::Signature: Serialize,
{
    type Error = JwtVcEncodeError;

    /// Encodes this verifiable credential into the claims of a JWT following
    /// the standard [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn to_jwt_claims(&self) -> Result<RegisteredClaims, JwtVcEncodeError> {
        encode_jwt_vc_claims(self)
    }
}

impl ToJwtClaims for super::SpecializedJsonCredential {
    type Error = JwtVcEncodeError;

    /// Encodes this credential into the claims of a JWT following the standard
    /// [JWT-VC encoding].
    ///
    /// [JWT-VC encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn to_jwt_claims(&self) -> Result<RegisteredClaims, JwtVcEncodeError> {
        encode_jwt_vc_claims(self)
    }
}

impl<C: DeserializeOwned, S> FromJwtClaims for DataIntegrity<super::JsonPresentation<C>, S>
where
    S: CryptographicSuite + TryFrom<ssi_data_integrity::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::ProofOptions: DeserializeOwned,
    S::Signature: DeserializeOwned,
{
    type Error = JwtVpDecodeError;

    /// Decodes a verifiable presentation from the claims of a JWT following the
    /// standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn from_jwt_claims(jwt: impl ClaimSet) -> Result<Self, JwtVpDecodeError> {
        decode_jwt_vp_claims(jwt)
    }
}

impl<C: Serialize, S: CryptographicSuite> ToJwtClaims
    for DataIntegrity<super::JsonPresentation<C>, S>
where
    S::VerificationMethod: Serialize,
    S::ProofOptions: Serialize,
    S::Signature: Serialize,
{
    type Error = JwtVpEncodeError;

    /// Encodes this verifiable presentation into the claims of a JWT following
    /// the standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn to_jwt_claims(&self) -> Result<RegisteredClaims, JwtVpEncodeError> {
        encode_jwt_vp_claims(self)
    }
}

impl<C: Serialize> ToJwtClaims for super::JsonPresentation<C> {
    type Error = JwtVpEncodeError;

    /// Encodes this presentation into the claims of a JWT following the
    /// standard [JWT-VP encoding].
    ///
    /// [JWT-VP encoding]: <https://www.w3.org/TR/vc-data-model/#jwt-encoding>
    fn to_jwt_claims(&self) -> Result<RegisteredClaims, JwtVpEncodeError> {
        encode_jwt_vp_claims(self)
    }
}
