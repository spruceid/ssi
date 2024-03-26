use std::{borrow::Cow, hash::Hash};

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_verification_methods_core::JwkVerificationMethod;
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationError, VerificationMethod,
};

pub const SOLANA_METHOD_2021_TYPE: &str = "SolanaMethod2021";

// pub const SOLANA_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#SolanaMethod2021");

/// Solana Method 2021.
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
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#SolanaMethod2021");

    pub fn public_key_jwk(&self) -> &JWK {
        &self.public_key
    }

    pub fn sign_bytes(
        // FIXME: check algorithm?
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

    fn ref_id(r: Self::Reference<'_>) -> &Iri {
        r.id.as_iri()
    }

    fn ref_controller(r: Self::Reference<'_>) -> Option<&Iri> {
        Some(r.controller.as_iri())
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

    fn ref_type(_r: Self::Reference<'_>) -> &str {
        SOLANA_METHOD_2021_TYPE
    }
}

impl JwkVerificationMethod for SolanaMethod2021 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Borrowed(self.public_key_jwk())
    }

    fn ref_to_jwk(r: Self::Reference<'_>) -> Cow<'_, JWK> {
        <Self as JwkVerificationMethod>::to_jwk(r)
    }
}

impl TryFrom<GenericVerificationMethod> for SolanaMethod2021 {
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
