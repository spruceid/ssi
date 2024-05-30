use ssi_jwk::JWK;

/// Options for all cryptographic suites.
#[derive(Debug, Clone, Default)]
pub struct AnyInputOptions {
    pub public_key_jwk: Option<Box<JWK>>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    pub eip712: Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>,
}

impl AnyInputOptions {
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

impl From<AnyInputOptions> for () {
    fn from(_: AnyInputOptions) -> Self {}
}

impl From<()> for AnyInputOptions {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>>
    for AnyInputOptions
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
impl From<AnyInputOptions> for ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options {
    fn from(value: AnyInputOptions) -> Self {
        Self {
            eip712: value.eip712,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options> for AnyInputOptions {
    fn from(value: ssi_data_integrity_suites::ethereum_eip712_signature_2021::Options) -> Self {
        Self {
            eip712: value.eip712,
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<AnyInputOptions>
    for ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Options
{
    fn from(value: AnyInputOptions) -> Self {
        Self {
            eip712: value.eip712.map(Into::into),
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Options>
    for AnyInputOptions
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
impl TryFrom<AnyInputOptions> for ssi_data_integrity_suites::tezos::Options {
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputOptions) -> Result<Self, Self::Error> {
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
impl From<ssi_data_integrity_suites::tezos::Options> for AnyInputOptions {
    fn from(value: ssi_data_integrity_suites::tezos::Options) -> Self {
        Self {
            public_key_jwk: Some(value.public_key_jwk),
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl TryFrom<AnyInputOptions> for ssi_data_integrity_suites::tezos_signature_2021::Options {
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_jwk: value.public_key_jwk,
        })
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos_signature_2021::Options> for AnyInputOptions {
    fn from(value: ssi_data_integrity_suites::tezos_signature_2021::Options) -> Self {
        Self {
            public_key_jwk: value.public_key_jwk,
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl TryFrom<AnyInputOptions>
    for ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::Options
{
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(value: AnyInputOptions) -> Result<Self, Self::Error> {
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
impl From<ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::Options> for AnyInputOptions {
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
