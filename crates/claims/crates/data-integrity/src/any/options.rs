use serde::{Deserialize, Serialize};
use ssi_data_integrity_core::ProofOptions;
use ssi_jwk::JWK;
use ssi_verification_methods::AnyMethod;

pub type AnyInputOptions = ProofOptions<AnyMethod, AnyInputSuiteOptions>;

/// Suite-specific options for all cryptographic suites.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnyInputSuiteOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Box<JWK>>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>,
}

impl AnyInputSuiteOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_key(self, jwk: JWK) -> Result<Self, ssi_jws::Error> {
        #[allow(clippy::needless_update)]
        Ok(Self {
            public_key_jwk: Some(Box::new(jwk)),
            ..self
        })
    }
}

impl From<AnyInputSuiteOptions> for () {
    fn from(_: AnyInputSuiteOptions) -> Self {}
}

impl From<()> for AnyInputSuiteOptions {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>>
    for AnyInputSuiteOptions
{
    fn from(
        value: Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>,
    ) -> Self {
        Self {
            eip712: value.clone(),
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<AnyInputSuiteOptions>
    for ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options
{
    fn from(value: AnyInputSuiteOptions) -> Self {
        Self {
            eip712: value.eip712,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options>
    for AnyInputSuiteOptions
{
    fn from(value: ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options) -> Self {
        Self {
            eip712: value.eip712,
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<AnyInputSuiteOptions>
    for ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Options
{
    fn from(value: AnyInputSuiteOptions) -> Self {
        Self {
            eip712: value.eip712.map(Into::into),
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Options>
    for AnyInputSuiteOptions
{
    fn from(
        value: ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Options,
    ) -> Self {
        Self {
            eip712: value.eip712.map(Into::into),
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl TryFrom<AnyInputSuiteOptions> for ssi_data_integrity_suites::tezos::Options {
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputSuiteOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_jwk: value.public_key_jwk.ok_or(
                ssi_data_integrity_core::suite::ConfigurationError::MissingOption(
                    "publicKeyJwk".to_string(),
                ),
            )?,
        })
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos::Options> for AnyInputSuiteOptions {
    fn from(value: ssi_data_integrity_suites::tezos::Options) -> Self {
        Self {
            public_key_jwk: Some(value.public_key_jwk),
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl TryFrom<AnyInputSuiteOptions> for ssi_data_integrity_suites::tezos_signature_2021::Options {
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputSuiteOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_jwk: value.public_key_jwk,
        })
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos_signature_2021::Options> for AnyInputSuiteOptions {
    fn from(value: ssi_data_integrity_suites::tezos_signature_2021::Options) -> Self {
        Self {
            public_key_jwk: value.public_key_jwk,
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl TryFrom<AnyInputSuiteOptions>
    for ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::Options
{
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputSuiteOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_multibase: value
                .public_key_jwk
                .as_deref()
                .map(ssi_data_integrity_suites::tezos::encode_jwk_to_multibase)
                .transpose()
                .map_err(ssi_data_integrity_core::suite::ConfigurationError::other)?,
        })
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::Options>
    for AnyInputSuiteOptions
{
    fn from(value: ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::Options) -> Self {
        Self {
            public_key_jwk: value
                .public_key_multibase
                .and_then(|key| {
                    ssi_data_integrity_suites::tezos::decode_jwk_from_multibase(&key).ok()
                })
                .map(Box::new),
            ..Default::default()
        }
    }
}
