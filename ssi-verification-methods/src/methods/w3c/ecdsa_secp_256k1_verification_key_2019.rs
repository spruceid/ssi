use std::{borrow::Cow, hash::Hash};

use hex::FromHexError;
use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SignatureError, TypedVerificationMethod, VerificationError, VerificationMethod,
};

pub const ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE: &str = "EcdsaSecp256k1VerificationKey2019";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "publicKeyHex")]
    #[ld("sec:publicKeyJwk")]
    Hex(String),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] FromHexError),

    #[error("invalid key bytes: {0}")]
    K256(#[from] k256::elliptic_curve::Error),
}

impl From<InvalidPublicKey> for VerificationError {
    fn from(_value: InvalidPublicKey) -> Self {
        Self::InvalidKey
    }
}

impl PublicKey {
    pub fn jwk(&self) -> Result<Cow<JWK>, InvalidPublicKey> {
        match self {
            Self::Jwk(jwk) => Ok(Cow::Borrowed(jwk)),
            Self::Hex(hex_encoded) => {
                let bytes = hex::decode(hex_encoded)?;
                let pk = k256::PublicKey::from_sec1_bytes(&bytes)?;
                let jwk = JWK {
                    params: ssi_jwk::Params::EC(ssi_jwk::ECParams::try_from(&pk).unwrap()),
                    public_key_use: None,
                    key_operations: None,
                    algorithm: None,
                    key_id: None,
                    x509_url: None,
                    x509_certificate_chain: None,
                    x509_thumbprint_sha1: None,
                    x509_thumbprint_sha256: None,
                };

                Ok(Cow::Owned(jwk))
            }
        }
    }
}

/// Key for [Ecdsa Secp256k1 Signature 2019][1].
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/#key-format>
///
/// [1]: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[serde(tag = "type", rename = "EcdsaSecp256k1VerificationKey2019")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:EcdsaSecp256k1VerificationKey2019")]
pub struct EcdsaSecp256k1VerificationKey2019 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Key controller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key.
    #[serde(flatten)]
    #[ld("sec:publicKey")]
    pub public_key: PublicKey,
}

impl EcdsaSecp256k1VerificationKey2019 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256K);
        let header = ssi_jws::Header::new_unencoded(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(&self, data: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
        let public_key = self
            .public_key
            .jwk()
            .map_err(|_| VerificationError::InvalidKey)?;
        if public_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256K) != ssi_jwk::Algorithm::ES256K
        {
            return Err(VerificationError::InvalidKey);
        }

        Ok(
            ssi_jws::verify_bytes(ssi_jwk::Algorithm::ES256K, data, &public_key, &signature)
                .is_ok(),
        )
    }
}

impl Referencable for EcdsaSecp256k1VerificationKey2019 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri {
        r.id.as_iri()
    }

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri> {
        Some(r.controller.as_iri())
    }
}

impl TypedVerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    fn expected_type() -> Option<ExpectedType> {
        Some(
            ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
                .to_string()
                .into(),
        )
    }

    fn type_match(ty: &str) -> bool {
        ty == ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
        ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for EcdsaSecp256k1VerificationKey2019 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        let public_key = match (
            m.properties.get("publicKeyJwk"),
            m.properties.get("publicKeyHex"),
        ) {
            (Some(k), None) => k
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?
                .parse()
                .map(|jwk| PublicKey::Jwk(Box::new(jwk)))
                .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?,
            (None, Some(k)) => k
                .as_str()
                .map(|s| PublicKey::Hex(s.to_owned()))
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyHex"))?,
            (Some(_), Some(_)) => return Err(InvalidVerificationMethod::AmbiguousPublicKey),
            (None, None) => {
                return Err(InvalidVerificationMethod::missing_property("publicKeyJwk"))
            }
        };

        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key,
        })
    }
}
