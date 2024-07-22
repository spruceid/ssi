use educe::Educe;
use serde::Serialize;
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwnedRef};
use std::collections::BTreeMap;

use crate::{
    CloneCryptographicSuite, CryptographicSuite, ProofConfiguration, SerializeCryptographicSuite,
};

#[derive(Educe, Serialize)]
#[educe(Clone, Copy)]
#[serde(bound = "S: SerializeCryptographicSuite", rename_all = "camelCase")]
pub struct ProofConfigurationRef<'a, S: CryptographicSuite> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a ssi_json_ld::syntax::Context>,

    /// Proof type.
    #[serde(flatten, serialize_with = "S::serialize_type")]
    pub type_: &'a S,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<xsd_types::DateTimeStamp>,

    #[serde(serialize_with = "S::serialize_verification_method_ref_ref")]
    pub verification_method: ReferenceOrOwnedRef<'a, S::VerificationMethod>,

    pub proof_purpose: ProofPurpose,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<xsd_types::DateTimeStamp>,

    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub domains: &'a [String],

    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,

    #[serde(flatten, serialize_with = "S::serialize_proof_options")]
    pub options: &'a S::ProofOptions,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}

impl<'a, S: CryptographicSuite> ProofConfigurationRef<'a, S> {
    pub fn to_owned(&self) -> ProofConfiguration<S>
    where
        S: CloneCryptographicSuite,
    {
        ProofConfiguration {
            context: self.context.cloned(),
            type_: self.type_.clone(),
            created: self.created,
            verification_method: S::clone_verification_method_ref_ref(self.verification_method),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains.to_owned(),
            challenge: self.challenge.map(ToOwned::to_owned),
            nonce: self.nonce.map(ToOwned::to_owned),
            options: S::clone_proof_options(self.options),
            extra_properties: self.extra_properties.clone(),
        }
    }

    pub fn map<T: CryptographicSuite>(
        self,
        map_type: impl FnOnce(&'a S) -> &'a T,
        map_verification_method: impl FnOnce(&'a S::VerificationMethod) -> &'a T::VerificationMethod,
        map_options: impl FnOnce(&'a S::ProofOptions) -> &'a T::ProofOptions,
    ) -> ProofConfigurationRef<'a, T> {
        ProofConfigurationRef {
            context: self.context,
            type_: map_type(self.type_),
            created: self.created,
            verification_method: self.verification_method.map(map_verification_method),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: map_options(self.options),
            extra_properties: self.extra_properties,
        }
    }

    pub fn try_map<T: CryptographicSuite, E>(
        self,
        map_type: impl FnOnce(&'a S) -> Result<&'a T, E>,
        map_verification_method: impl FnOnce(
            &'a S::VerificationMethod,
        ) -> Result<&'a T::VerificationMethod, E>,
        map_options: impl FnOnce(&'a S::ProofOptions) -> Result<&'a T::ProofOptions, E>,
    ) -> Result<ProofConfigurationRef<'a, T>, E> {
        Ok(ProofConfigurationRef {
            context: self.context,
            type_: map_type(self.type_)?,
            created: self.created,
            verification_method: self.verification_method.try_map(map_verification_method)?,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: map_options(self.options)?,
            extra_properties: self.extra_properties,
        })
    }

    pub fn without_proof_options(self) -> ProofConfigurationRefWithoutOptions<'a, S> {
        ProofConfigurationRefWithoutOptions {
            context: self.context,
            type_: self.type_,
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            extra_properties: self.extra_properties,
        }
    }
}

/// Proof configuration without the suite specific options.
#[derive(Educe, Serialize)]
#[educe(Clone, Copy)]
#[serde(bound = "S: SerializeCryptographicSuite", rename_all = "camelCase")]
pub struct ProofConfigurationRefWithoutOptions<'a, S: CryptographicSuite> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a ssi_json_ld::syntax::Context>,

    /// Proof type.
    #[serde(flatten, serialize_with = "S::serialize_type")]
    pub type_: &'a S,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<xsd_types::DateTimeStamp>,

    #[serde(serialize_with = "S::serialize_verification_method_ref_ref")]
    pub verification_method: ReferenceOrOwnedRef<'a, S::VerificationMethod>,

    pub proof_purpose: ProofPurpose,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<xsd_types::DateTimeStamp>,

    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub domains: &'a [String],

    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}
