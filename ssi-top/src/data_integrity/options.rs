use ssi_jwk::JWK;
use ssi_vc_ldp::suite::CryptographicSuiteOptions;
use ssi_verification_methods::{covariance_rule, Referencable, SignatureError, VerificationError};

use crate::AnySuite;

/// Options for all cryptographic suites.
#[derive(
    Debug,
    Clone,
    Default,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
pub struct AnySuiteOptions {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Box<JWK>>,

    #[ld("eip712:eip712")]
    pub eip712: Option<ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options>,
}

impl AnySuiteOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_key(jwk: JWK) -> Self {
        Self {
            public_key_jwk: Some(Box::new(jwk)),
            eip712: None,
        }
    }
}

impl From<Option<ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options>>
    for AnySuiteOptions
{
    fn from(
        value: Option<ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options>,
    ) -> Self {
        Self {
            eip712: value,
            ..Default::default()
        }
    }
}

impl From<ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options> for AnySuiteOptions {
    fn from(value: ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options) -> Self {
        Self {
            eip712: Some(value),
            ..Default::default()
        }
    }
}

impl Referencable for AnySuiteOptions {
    type Reference<'a> = AnySuiteOptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySuiteOptionsRef {
            public_key_jwk: self.public_key_jwk.as_deref(),
            eip712: self.eip712.as_ref(),
        }
    }

    covariance_rule!();
}

impl CryptographicSuiteOptions<AnySuite> for AnySuiteOptions {
    fn prepare(&mut self, suite: &AnySuite) {
        if !suite.requires_public_key_jwk() {
            self.public_key_jwk = None
        }
    }
}

#[derive(Clone, Default, Copy)]
pub struct AnySuiteOptionsRef<'a> {
    pub public_key_jwk: Option<&'a JWK>,

    pub eip712: Option<&'a ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Eip712Options>,
}

impl<'a> From<AnySuiteOptionsRef<'a>> for () {
    fn from(_value: AnySuiteOptionsRef<'a>) -> Self {
        ()
    }
}

#[cfg(feature = "tezos")]
impl<'a> TryFrom<AnySuiteOptionsRef<'a>> for ssi_vc_ldp::suite::tezos::OptionsRef<'a> {
    type Error = InvalidOptions;

    fn try_from(value: AnySuiteOptionsRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_jwk: value
                .public_key_jwk
                .ok_or(InvalidOptions::MissingPublicKey)?,
        })
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl<'a> From<AnySuiteOptionsRef<'a>>
    for ssi_vc_ldp::suite::ethereum_eip712_signature_2021::OptionsRef<'a>
{
    fn from(value: AnySuiteOptionsRef<'a>) -> Self {
        Self {
            eip712: value.eip712,
        }
    }
}

pub enum InvalidOptions {
    MissingPublicKey,
}

impl From<InvalidOptions> for VerificationError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => VerificationError::MissingPublicKey,
        }
    }
}

impl From<InvalidOptions> for SignatureError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => SignatureError::MissingPublicKey,
        }
    }
}
