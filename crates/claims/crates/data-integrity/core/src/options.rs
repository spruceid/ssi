use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

use crate::{suite::ConfigurationError, CryptographicSuite, ProofConfiguration};

/// Proof options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOptions<M, T> {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<ssi_json_ld::syntax::Context>,

    /// Date a creation of the proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<xsd_types::DateTimeStamp>,

    /// Verification method.
    pub verification_method: Option<ReferenceOrOwned<M>>,

    /// Purpose of the proof.
    #[serde(default)]
    pub proof_purpose: ProofPurpose,

    /// Specifies when the proof expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,

    /// Used to mitigate replay attacks.
    ///
    /// Used once for a particular domain and window of time. Examples of a
    /// challenge value include: `1235abcd6789`,
    /// `79d34551-ae81-44ae-823b-6dadbab9ebd4`, and `ruby`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Arbitrary string supplied by the proof creator.
    ///
    /// One use of this field is to increase privacy by decreasing linkability
    /// that is the result of deterministically generated signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    #[serde(flatten)]
    pub options: T,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<M, T: Default> Default for ProofOptions<M, T> {
    fn default() -> Self {
        Self {
            context: None,
            created: Some(xsd_types::DateTimeStamp::now_ms()),
            verification_method: None,
            proof_purpose: ProofPurpose::default(),
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options: Default::default(),
            extra_properties: BTreeMap::new(),
        }
    }
}

impl<M, T> ProofOptions<M, T> {
    pub fn new(
        created: xsd_types::DateTimeStamp,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
        options: T,
    ) -> Self {
        Self {
            context: None,
            created: Some(created),
            verification_method: Some(verification_method),
            proof_purpose,
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method_and_options(verification_method: ReferenceOrOwned<M>, options: T) -> Self {
        Self {
            context: None,
            created: Some(xsd_types::DateTimeStamp::now_ms()),
            verification_method: Some(verification_method),
            proof_purpose: ProofPurpose::default(),
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method(verification_method: ReferenceOrOwned<M>) -> Self
    where
        T: Default,
    {
        Self::from_method_and_options(verification_method, Default::default())
    }

    pub fn map<N, U>(
        self,
        map_verification_method: impl FnOnce(M) -> N,
        map_options: impl FnOnce(T) -> U,
    ) -> ProofOptions<N, U> {
        ProofOptions {
            context: self.context,
            created: self.created,
            verification_method: self
                .verification_method
                .map(|m| m.map(map_verification_method)),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: map_options(self.options),
            extra_properties: self.extra_properties,
        }
    }

    pub fn cast<N, U>(self) -> ProofOptions<N, U>
    where
        M: Into<N>,
        T: Into<U>,
    {
        self.map(Into::into, Into::into)
    }

    pub fn try_map<N, U, E>(
        self,
        map_verification_method: impl FnOnce(M) -> Result<N, E>,
        map_options: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<ProofOptions<N, U>, E> {
        Ok(ProofOptions {
            context: self.context,
            created: self.created,
            verification_method: self
                .verification_method
                .map(|m| m.try_map(map_verification_method))
                .transpose()?,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: map_options(self.options)?,
            extra_properties: self.extra_properties,
        })
    }

    pub fn into_configuration_with<S>(
        self,
        type_: S,
        f: impl FnOnce(T) -> S::ProofOptions,
    ) -> Result<ProofConfiguration<S>, ConfigurationError>
    where
        S: CryptographicSuite<VerificationMethod = M>,
    {
        Ok(ProofConfiguration {
            context: self.context,
            type_,
            created: self.created,
            verification_method: self
                .verification_method
                .ok_or(ConfigurationError::MissingVerificationMethod)?,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: f(self.options),
            extra_properties: self.extra_properties,
        })
    }

    pub fn into_configuration<S>(
        self,
        type_: S,
    ) -> Result<ProofConfiguration<S>, ConfigurationError>
    where
        S: CryptographicSuite<VerificationMethod = M, ProofOptions = T>,
    {
        self.into_configuration_with(type_, |o| o)
    }
}
