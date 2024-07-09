use std::{borrow::Cow, hash::Hash};

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::JWK;
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationMethodSet};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
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
    pub const NAME: &'static str = RSA_VERIFICATION_KEY_2018_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#RsaVerificationKey2018");

    pub fn public_key_jwk(&self) -> &JWK {
        &self.public_key
    }

    pub fn sign_bytes(
        &self,
        data: &[u8],
        secret_key: &JWK,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(ssi_jwk::Algorithm::RS256, data, secret_key)
            .map_err(|_| MessageSignatureError::InvalidSecretKey)
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        let result =
            ssi_jws::verify_bytes(ssi_jwk::Algorithm::RS256, data, &self.public_key, signature);
        match result {
            Ok(()) => Ok(Ok(())),
            Err(ssi_jws::Error::InvalidSignature) => Ok(Err(InvalidProof::Signature)),
            Err(_) => Err(ProofValidationError::InvalidSignature),
        }
    }
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

impl VerificationMethodSet for RsaVerificationKey2018 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
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

impl JwkVerificationMethod for RsaVerificationKey2018 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Borrowed(self.public_key_jwk())
    }
}

impl TryFrom<GenericVerificationMethod> for RsaVerificationKey2018 {
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
