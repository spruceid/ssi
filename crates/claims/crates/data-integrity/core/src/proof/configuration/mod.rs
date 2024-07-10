use iref::Iri;
use serde::Serialize;
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};
use static_iref::iri;
use std::collections::BTreeMap;

use crate::{CryptographicSuite, Proof, ProofOptions, SerializeCryptographicSuite};

pub const DC_CREATED_IRI: &Iri = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: &Iri = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

mod expansion;
mod reference;

pub use expansion::*;
pub use reference::*;

/// Proof configuration.
///
/// Proof object without the signature value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", bound = "S: SerializeCryptographicSuite")]
pub struct ProofConfiguration<S: CryptographicSuite> {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ssi_json_ld::syntax::Context>,

    /// Proof type.
    #[serde(flatten, serialize_with = "S::serialize_type")]
    pub type_: S,

    /// Date a creation of the proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<xsd_types::DateTimeStamp>,

    /// Verification method.
    #[serde(serialize_with = "S::serialize_verification_method_ref")]
    pub verification_method: ReferenceOrOwned<S::VerificationMethod>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Specifies when the proof expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<xsd_types::DateTimeStamp>,

    #[allow(rustdoc::bare_urls)]
    /// Conveys one or more security domains in which the proof is meant to be
    /// used.
    ///
    /// A verifier SHOULD use the value to ensure that the proof was intended to
    /// be used in the security domain in which the verifier is operating. The
    /// specification of the domain parameter is useful in challenge-response
    /// protocols where the verifier is operating from within a security domain
    /// known to the creator of the proof.
    ///
    /// Example domain values include: `domain.example`` (DNS domain),
    /// `https://domain.example:8443` (Web origin), `mycorp-intranet` (bespoke
    /// text string), and `b31d37d4-dd59-47d3-9dd8-c973da43b63a` (UUID).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,

    /// Used to mitigate replay attacks.
    ///
    /// Used once for a particular domain and window of time. Examples of a
    /// challenge value include: `1235abcd6789`,
    /// `79d34551-ae81-44ae-823b-6dadbab9ebd4`, and `ruby`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Arbitrary string supplied by the proof creator.
    ///
    /// One use of this field is to increase privacy by decreasing linkability
    /// that is the result of deterministically generated signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    #[serde(flatten, serialize_with = "S::serialize_proof_options")]
    pub options: S::ProofOptions,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<S: CryptographicSuite> ProofConfiguration<S> {
    pub fn new(
        type_: S,
        created: xsd_types::DateTimeStamp,
        verification_method: ReferenceOrOwned<S::VerificationMethod>,
        proof_purpose: ProofPurpose,
        options: S::ProofOptions,
    ) -> Self {
        Self {
            context: None,
            type_,
            created: Some(created),
            verification_method,
            proof_purpose,
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method_and_options(
        type_: S,
        verification_method: ReferenceOrOwned<S::VerificationMethod>,
        options: S::ProofOptions,
    ) -> Self {
        Self {
            context: None,
            type_,
            created: Some(xsd_types::DateTimeStamp::now_ms()),
            verification_method,
            proof_purpose: ProofPurpose::default(),
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method(
        type_: S,
        verification_method: ReferenceOrOwned<S::VerificationMethod>,
    ) -> Self
    where
        S::ProofOptions: Default,
    {
        Self::from_method_and_options(type_, verification_method, Default::default())
    }

    pub fn into_suite_and_options(
        self,
    ) -> (S, ProofOptions<S::VerificationMethod, S::ProofOptions>) {
        (
            self.type_,
            ProofOptions {
                context: self.context,
                created: self.created,
                verification_method: Some(self.verification_method),
                proof_purpose: self.proof_purpose,
                expires: self.expires,
                domains: self.domains,
                challenge: self.challenge,
                nonce: self.nonce,
                options: self.options,
                extra_properties: self.extra_properties,
            },
        )
    }

    pub fn into_options(self) -> ProofOptions<S::VerificationMethod, S::ProofOptions> {
        ProofOptions {
            context: self.context,
            created: self.created,
            verification_method: Some(self.verification_method),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: self.options,
            extra_properties: self.extra_properties,
        }
    }

    pub fn into_proof(self, signature: S::Signature) -> Proof<S> {
        Proof {
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
            signature,
            extra_properties: self.extra_properties,
        }
    }

    pub fn map<T: CryptographicSuite>(
        self,
        map_type: impl FnOnce(S) -> T,
        map_verification_method: impl FnOnce(S::VerificationMethod) -> T::VerificationMethod,
        map_options: impl FnOnce(S::ProofOptions) -> T::ProofOptions,
    ) -> ProofConfiguration<T> {
        ProofConfiguration {
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

    pub fn borrowed(&self) -> ProofConfigurationRef<S> {
        ProofConfigurationRef {
            context: self.context.as_ref(),
            type_: &self.type_,
            created: self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: &self.domains,
            challenge: self.challenge.as_deref(),
            nonce: self.nonce.as_deref(),
            options: &self.options,
            extra_properties: &self.extra_properties,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofConfigurationCastError<M, O> {
    #[error("invalid verification method")]
    VerificationMethod(M),

    #[error("invalid options")]
    Options(O),
}
