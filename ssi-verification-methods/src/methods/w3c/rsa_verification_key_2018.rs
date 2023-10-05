use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SignatureError, TypedVerificationMethod, VerificationMethod,
};

pub const RSA_VERIFICATION_KEY_2018_TYPE: &str = "RsaVerificationKey2018";

// pub const RSA_VERIFICATION_KEY_2018_IRI: &Iri =
//     iri!("https://w3id.org/security#RsaVerificationKey2018");

/// RSA verification key 2018.
///
/// To be used with the [RSA Signature Suite 2018][1].
///
/// See: <https://www.w3.org/TR/did-spec-registries/#rsaverificationkey2018>
///
/// [1]: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "RsaVerificationKey2018")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:RsaVerificationKey2018")]
pub struct RsaVerificationKey2018 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Key crontroller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public JSON Web Key.
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key: Box<JWK>,
}

impl RsaVerificationKey2018 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<String, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(ssi_jwk::Algorithm::RS256, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::RS256, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(multibase::Base::Base64.encode(signature))
    }
}

impl Referencable for RsaVerificationKey2018 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for RsaVerificationKey2018 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for RsaVerificationKey2018 {
    fn expected_type() -> Option<ExpectedType> {
        Some(RSA_VERIFICATION_KEY_2018_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == RSA_VERIFICATION_KEY_2018_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        RSA_VERIFICATION_KEY_2018_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for RsaVerificationKey2018 {
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
