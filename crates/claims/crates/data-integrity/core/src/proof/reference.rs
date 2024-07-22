use std::collections::BTreeMap;

use ssi_verification_methods::{ProofPurpose, ReferenceOrOwnedRef};

use crate::{CryptographicSuite, ProofConfigurationRef};

pub struct ProofRef<'a, S: CryptographicSuite> {
    pub context: Option<&'a ssi_json_ld::syntax::Context>,

    pub type_: &'a S,

    pub created: Option<xsd_types::DateTimeStamp>,

    pub verification_method: ReferenceOrOwnedRef<'a, S::VerificationMethod>,

    pub proof_purpose: ProofPurpose,

    pub expires: Option<xsd_types::DateTimeStamp>,

    pub domains: &'a [String],

    pub challenge: Option<&'a str>,

    pub nonce: Option<&'a str>,

    pub options: &'a S::ProofOptions,

    pub signature: &'a S::Signature,

    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}

impl<'a, S: CryptographicSuite> ProofRef<'a, S> {
    pub fn configuration(&self) -> ProofConfigurationRef<'a, S> {
        ProofConfigurationRef {
            context: self.context,
            type_: self.type_,
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: self.options,
            extra_properties: self.extra_properties,
        }
    }

    pub fn map<T: CryptographicSuite>(
        self,
        map_type: impl FnOnce(&'a S) -> &'a T,
        map_verification_method: impl FnOnce(&'a S::VerificationMethod) -> &'a T::VerificationMethod,
        map_options: impl FnOnce(&'a S::ProofOptions) -> &'a T::ProofOptions,
        map_signature: impl FnOnce(&'a S::Signature) -> &'a T::Signature,
    ) -> ProofRef<'a, T> {
        ProofRef {
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
            signature: map_signature(self.signature),
            extra_properties: self.extra_properties,
        }
    }
}
