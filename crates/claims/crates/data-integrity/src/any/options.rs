use ssi_core::{covariance_rule, Referencable};
use ssi_data_integrity_core::suite::{CryptographicSuiteOptions, InvalidOptions};
use ssi_jwk::JWK;
use ssi_security::{Multibase, MultibaseBuf};

use super::AnySuite;

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
#[ld(prefix("eip712v0.1" = "https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#"))]
pub struct AnySuiteOptions {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Box<JWK>>,

    #[serde(rename = "publicKeyMultibase")]
    #[ld("sec:publicKeyMultibase")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<MultibaseBuf>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    #[ld("eip712:eip712-domain")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    #[ld("eip712v0.1:eip712-domain")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eip712Domain")]
    pub eip712_v0_1:
        Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Eip712Options>,
}

impl AnySuiteOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_key(self, jwk: JWK) -> Result<Self, ssi_jws::Error> {
        let public_key_multibase = Some(ssi_data_integrity_suites::tezos::encode_jwk_to_multibase(
            &jwk,
        )?);
        Ok(Self {
            public_key_jwk: Some(Box::new(jwk)),
            public_key_multibase,
            ..self
        })
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl From<Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>>
    for AnySuiteOptions
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
impl From<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options>
    for AnySuiteOptions
{
    fn from(
        value: ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options,
    ) -> Self {
        Self {
            eip712: Some(value.clone()),
            ..Default::default()
        }
    }
}

impl Referencable for AnySuiteOptions {
    type Reference<'a> = AnySuiteOptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySuiteOptionsRef {
            public_key_jwk: self.public_key_jwk.as_deref(),
            public_key_multibase: self.public_key_multibase.as_deref(),
            #[cfg(all(feature = "w3c", feature = "eip712"))]
            eip712: self
                .eip712
                .as_ref()
                .map(ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options::as_ref),
            #[cfg(all(feature = "w3c", feature = "eip712"))]
            eip712_v0_1: self.eip712_v0_1.as_ref().map(
                ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Eip712Options::as_ref,
            ),
        }
    }

    covariance_rule!();
}

impl CryptographicSuiteOptions<AnySuite> for AnySuiteOptions {
    fn prepare(&mut self, suite: &AnySuite) {
        if !suite.requires_public_key_jwk() {
            self.public_key_jwk = None
        }

        if !suite.requires_public_key_multibase() {
            self.public_key_multibase = None
        }

        #[cfg(all(feature = "w3c", feature = "eip712"))]
        if !suite.requires_eip721() {
            self.eip712 = None
        }

        #[cfg(all(feature = "w3c", feature = "eip712"))]
        if !suite.requires_eip721_v0_1() {
            self.eip712_v0_1 = None
        }
    }
}

#[derive(Debug, Clone, Default, Copy, serde::Serialize)]
pub struct AnySuiteOptionsRef<'a> {
    #[serde(rename = "publicKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<&'a JWK>,

    #[serde(rename = "publicKeyMultibase")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<&'a Multibase>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712:
        Option<ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712OptionsRef<'a>>,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eip712Domain")]
    pub eip712_v0_1: Option<
        ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Eip712OptionsRef<'a>,
    >,
}

impl<'a> From<AnySuiteOptionsRef<'a>> for () {
    fn from(_value: AnySuiteOptionsRef<'a>) -> Self {}
}

#[cfg(feature = "tezos")]
impl<'a> TryFrom<AnySuiteOptionsRef<'a>> for ssi_data_integrity_suites::tezos::OptionsRef<'a> {
    type Error = InvalidOptions;

    fn try_from(value: AnySuiteOptionsRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key_jwk: value
                .public_key_jwk
                .ok_or(InvalidOptions::MissingPublicKey)?,
        })
    }
}

#[cfg(feature = "tezos")]
impl<'a> From<AnySuiteOptionsRef<'a>>
    for ssi_data_integrity_suites::tezos::tezos_signature_2021::OptionsRef<'a>
{
    fn from(value: AnySuiteOptionsRef<'a>) -> Self {
        Self {
            public_key_jwk: value.public_key_jwk,
        }
    }
}

#[cfg(feature = "tezos")]
impl<'a> From<AnySuiteOptionsRef<'a>>
    for ssi_data_integrity_suites::tezos::tezos_jcs_signature_2021::OptionsRef<'a>
{
    fn from(value: AnySuiteOptionsRef<'a>) -> Self {
        Self {
            public_key_multibase: value.public_key_multibase,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl<'a> From<AnySuiteOptionsRef<'a>>
    for ssi_data_integrity_suites::ethereum_eip712_signature_2021::OptionsRef<'a>
{
    fn from(value: AnySuiteOptionsRef<'a>) -> Self {
        Self {
            eip712: value.eip712,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
impl<'a> From<AnySuiteOptionsRef<'a>>
    for ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::OptionsRef<'a>
{
    fn from(value: AnySuiteOptionsRef<'a>) -> Self {
        Self {
            eip712: value.eip712_v0_1,
        }
    }
}
