use std::{borrow::Cow, hash::Hash};

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::{Algorithm, JWK};
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationMethodSet, VerifyBytes};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

pub const JSON_WEB_KEY_2020_TYPE: &str = "JsonWebKey2020";

/// JSON Web Key 2020 verification method.
///
/// To be used with the [JSON Web Signature 2020][1] cryptographic suite.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020>
///
/// [1]: <https://w3c-ccg.github.io/lds-jws2020>
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[serde(tag = "type", rename = "JsonWebKey2020")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:JsonWebKey2020")]
pub struct JsonWebKey2020 {
    /// Key identifier.
    ///
    /// Should be the JWK thumbprint calculated from the public key value
    /// according to [RFC7638][rfc7638].
    ///
    /// [rfc7638]: <https://w3c-ccg.github.io/lds-jws2020/#bib-rfc7638>
    #[ld(id)]
    pub id: IriBuf,

    /// Key controller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public JSON Web Key.
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key: Box<JWK>,
}

impl JsonWebKey2020 {
    pub const NAME: &'static str = JSON_WEB_KEY_2020_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#JsonWebKey2020");

    pub fn public_key_jwk(&self) -> &JWK {
        &self.public_key
    }

    pub fn sign_bytes(
        &self,
        secret_key: &JWK,
        algorithm: Option<ssi_jwk::Algorithm>,
        data: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .or(secret_key.algorithm)
            .ok_or(MessageSignatureError::InvalidSecretKey)?;
        ssi_jws::sign_bytes(algorithm, data, secret_key)
            .map_err(|_| MessageSignatureError::InvalidSecretKey)
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature: &[u8],
        algorithm: Option<Algorithm>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let algorithm = match (self.public_key.algorithm, algorithm) {
            (Some(a), Some(b)) => {
                if a == b {
                    a
                } else {
                    return Ok(Err(InvalidProof::AlgorithmMismatch));
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return Err(ProofValidationError::InvalidKey),
        };

        Ok(
            ssi_jws::verify_bytes(algorithm, data, &self.public_key, signature)
                .map_err(|_| InvalidProof::Signature),
        )
    }
}

impl VerificationMethod for JsonWebKey2020 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for JsonWebKey2020 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for JsonWebKey2020 {
    fn expected_type() -> Option<ExpectedType> {
        Some(JSON_WEB_KEY_2020_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == JSON_WEB_KEY_2020_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        JSON_WEB_KEY_2020_TYPE
    }
}

impl JwkVerificationMethod for JsonWebKey2020 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Borrowed(self.public_key_jwk())
    }
}

impl VerifyBytes<Algorithm> for JsonWebKey2020 {
    fn verify_bytes(
        &self,
        algorithm: Algorithm,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        self.verify_bytes(signing_bytes, signature, Some(algorithm))
    }
}

impl TryFrom<GenericVerificationMethod> for JsonWebKey2020 {
    type Error = InvalidVerificationMethod;

    fn try_from(mut m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key: Box::new(
                serde_json::from_value(
                    m.properties.remove("publicKeyJwk").ok_or_else(|| {
                        InvalidVerificationMethod::missing_property("publicKeyJwk")
                    })?,
                )
                .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?,
            ),
        })
    }
}
