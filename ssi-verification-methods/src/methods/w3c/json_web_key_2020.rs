use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SignatureError, TypedVerificationMethod, VerificationError, VerificationMethod,
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
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key
            .algorithm
            .ok_or(SignatureError::InvalidSecretKey)?;
        let header = ssi_jws::Header::new_unencoded(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(&self, data: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
        match self.public_key.algorithm.as_ref() {
            Some(a) => Ok(ssi_jws::verify_bytes(*a, data, &self.public_key, signature).is_ok()),
            None => Err(VerificationError::InvalidKey),
        }
    }
}

impl Referencable for JsonWebKey2020 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
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

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri {
        r.id.as_iri()
    }

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri> {
        Some(r.controller.as_iri())
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

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
        JSON_WEB_KEY_2020_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for JsonWebKey2020 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key: Box::new(
                m.properties
                    .get("publicKeyJwk")
                    .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyJwk"))?
                    .as_str()
                    .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?
                    .parse()
                    .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?,
            ),
        })
    }
}
