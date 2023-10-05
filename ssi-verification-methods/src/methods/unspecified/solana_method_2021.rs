use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SignatureError, TypedVerificationMethod, VerificationError, VerificationMethod,
};

pub const SOLANA_METHOD_2021_TYPE: &str = "SolanaMethod2021";

// pub const SOLANA_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#SolanaMethod2021");

/// Solana Method 2021.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "SolanaMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:SolanaMethod2021")]
pub struct SolanaMethod2021 {
    /// Key identifier.
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

impl SolanaMethod2021 {
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

impl Referencable for SolanaMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for SolanaMethod2021 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for SolanaMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(SOLANA_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == SOLANA_METHOD_2021_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        SOLANA_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for SolanaMethod2021 {
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
