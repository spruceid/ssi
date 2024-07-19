use crate::suite::bounds::{OptionsRefOf, SignatureRefOf, VerificationMethodRefOf};
use crate::suite::{
    CryptographicSuiteVerification, InputVerificationOptions, SerializeCryptographicSuite,
};
use crate::{
    CloneCryptographicSuite, CryptographicSuite, DataIntegrity, DebugCryptographicSuite,
    DeserializeCryptographicSuite,
};
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{AttachProof, ProofValidationError, ProofValidity, ResourceProvider};
use ssi_core::{one_or_many::OneOrManyRef, OneOrMany};
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};
use std::collections::BTreeMap;
use std::{
    borrow::{Borrow, BorrowMut},
    fmt,
    ops::{Deref, DerefMut},
};

mod de;

mod configuration;
// mod prepared;
mod reference;
mod r#type;

pub use configuration::*;
// pub use prepared::*;
pub use r#type::*;
pub use reference::*;

/// Data Integrity Proof.
///
/// A data integrity proof provides information about the proof mechanism,
/// parameters required to verify that proof, and the proof value itself.
#[derive(Serialize)]
#[serde(bound = "S: SerializeCryptographicSuite", rename_all = "camelCase")]
pub struct Proof<S: CryptographicSuite> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ssi_json_ld::syntax::Context>,

    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    #[serde(flatten, serialize_with = "S::serialize_type")]
    pub type_: S,

    /// Date a creation of the proof.
    #[serde(
        deserialize_with = "de::deserialize_datetime_utc",
        skip_serializing_if = "Option::is_none"
    )]
    pub created: Option<xsd_types::DateTimeStamp>,

    /// Verification method.
    #[serde(serialize_with = "S::serialize_verification_method_ref")]
    pub verification_method: ReferenceOrOwned<S::VerificationMethod>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Specifies when the proof expires.
    #[serde(
        deserialize_with = "de::deserialize_datetime_utc",
        skip_serializing_if = "Option::is_none"
    )]
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

    /// Proof signature.
    #[serde(flatten, serialize_with = "S::serialize_signature")]
    pub signature: S::Signature,

    /// Extra properties unrelated to the cryptographic suite.
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<T: CryptographicSuite> Proof<T> {
    /// Creates a new proof.
    pub fn new(
        type_: T,
        created: xsd_types::DateTimeStamp,
        verification_method: ReferenceOrOwned<T::VerificationMethod>,
        proof_purpose: ProofPurpose,
        options: T::ProofOptions,
        signature: T::Signature,
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
            signature,
            extra_properties: Default::default(),
        }
    }

    pub fn borrowed(&self) -> ProofRef<T> {
        ProofRef {
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
            signature: &self.signature,
            extra_properties: &self.extra_properties,
        }
    }

    pub fn with_context(self, context: ssi_json_ld::syntax::Context) -> Self {
        Self {
            context: Some(context),
            ..self
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }

    pub fn configuration(&self) -> ProofConfigurationRef<T> {
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

    pub fn map_type<U: CryptographicSuite>(
        self,
        type_: impl FnOnce(T) -> U,
        verification_method: impl FnOnce(T::VerificationMethod) -> U::VerificationMethod,
        options: impl FnOnce(T::ProofOptions) -> U::ProofOptions,
        signature: impl FnOnce(T::Signature) -> U::Signature,
    ) -> Proof<U> {
        Proof {
            context: self.context,
            type_: type_(self.type_),
            created: self.created,
            verification_method: self.verification_method.map(verification_method),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: options(self.options),
            signature: signature(self.signature),
            extra_properties: self.extra_properties,
        }
    }
}

impl<S: CloneCryptographicSuite> Clone for Proof<S> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            type_: self.type_.clone(),
            created: self.created,
            verification_method: S::clone_verification_method_ref(&self.verification_method),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains.clone(),
            challenge: self.challenge.clone(),
            nonce: self.nonce.clone(),
            options: S::clone_proof_options(&self.options),
            signature: S::clone_signature(&self.signature),
            extra_properties: self.extra_properties.clone(),
        }
    }
}

impl<S: DebugCryptographicSuite> fmt::Debug for Proof<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proof")
            .field("context", &self.context)
            .field("type_", &self.type_)
            .field("created", &self.created)
            .field(
                "verification_method",
                &VerificationMethodRefOf::<S>(self.verification_method.borrowed()),
            )
            .field("proof_purpose", &self.proof_purpose)
            .field("expires", &self.expires)
            .field("domains", &self.domains)
            .field("challenge", &self.challenge)
            .field("nonce", &self.nonce)
            .field("options", &OptionsRefOf::<S>(&self.options))
            .field("signature", &SignatureRefOf::<S>(&self.signature))
            .field("extra_properties", &self.extra_properties)
            .finish()
    }
}

impl<S: CryptographicSuite, T, V> ssi_claims_core::ValidateProof<V, T> for Proof<S>
where
    S: CryptographicSuiteVerification<T, V>,
    V: ResourceProvider<InputVerificationOptions<S>>,
{
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a T,
    ) -> Result<ProofValidity, ProofValidationError> {
        let transformation_options = self
            .suite()
            .configure_verification(verifier.get_resource())?;
        self.suite()
            .verify_proof(verifier, claims, self.borrowed(), transformation_options)
            .await
    }
}

impl<T, S: CryptographicSuite> AttachProof<T> for Proof<S> {
    type Attached = DataIntegrity<T, S>;

    fn attach_to(self, claims: T) -> Self::Attached {
        DataIntegrity::new(claims, self.into())
    }
}

/// Set of Data-Integrity proofs.
#[derive(Educe)]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Default)]
pub struct Proofs<S: CryptographicSuite>(pub(crate) Vec<Proof<S>>);

impl<S: CryptographicSuite> Proofs<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[Proof<S>] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [Proof<S>] {
        &mut self.0
    }

    pub fn iter(&self) -> std::slice::Iter<Proof<S>> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<Proof<S>> {
        self.0.iter_mut()
    }
}

impl<S: CryptographicSuite> Deref for Proofs<S> {
    type Target = Vec<Proof<S>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: CryptographicSuite> DerefMut for Proofs<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<S: CryptographicSuite> Borrow<[Proof<S>]> for Proofs<S> {
    fn borrow(&self) -> &[Proof<S>] {
        self.as_slice()
    }
}

impl<S: CryptographicSuite> BorrowMut<[Proof<S>]> for Proofs<S> {
    fn borrow_mut(&mut self) -> &mut [Proof<S>] {
        self.as_mut_slice()
    }
}

impl<S: CryptographicSuite> AsRef<[Proof<S>]> for Proofs<S> {
    fn as_ref(&self) -> &[Proof<S>] {
        self.as_slice()
    }
}

impl<S: CryptographicSuite> AsMut<[Proof<S>]> for Proofs<S> {
    fn as_mut(&mut self) -> &mut [Proof<S>] {
        self.as_mut_slice()
    }
}

impl<S: CryptographicSuite> From<Proof<S>> for Proofs<S> {
    fn from(value: Proof<S>) -> Self {
        Self(vec![value])
    }
}

impl<S: CryptographicSuite> From<Vec<Proof<S>>> for Proofs<S> {
    fn from(value: Vec<Proof<S>>) -> Self {
        Self(value)
    }
}

impl<S: CryptographicSuite> FromIterator<Proof<S>> for Proofs<S> {
    fn from_iter<T: IntoIterator<Item = Proof<S>>>(iter: T) -> Self {
        Proofs(Vec::from_iter(iter))
    }
}

impl<S: CryptographicSuite, T, V> ssi_claims_core::ValidateProof<V, T> for Proofs<S>
where
    S: CryptographicSuiteVerification<T, V>,
    V: ResourceProvider<InputVerificationOptions<S>>,
{
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a T,
    ) -> Result<ProofValidity, ProofValidationError> {
        self.0.validate_proof(verifier, claims).await
    }
}

impl<T, S: CryptographicSuite> AttachProof<T> for Proofs<S> {
    type Attached = DataIntegrity<T, S>;

    fn attach_to(self, claims: T) -> Self::Attached {
        DataIntegrity::new(claims, self)
    }
}

impl<S: CryptographicSuite> Extend<Proof<S>> for Proofs<S> {
    fn extend<T: IntoIterator<Item = Proof<S>>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

impl<S: CryptographicSuite> IntoIterator for Proofs<S> {
    type IntoIter = std::vec::IntoIter<Proof<S>>;
    type Item = Proof<S>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, S: CryptographicSuite> IntoIterator for &'a Proofs<S> {
    type IntoIter = std::slice::Iter<'a, Proof<S>>;
    type Item = &'a Proof<S>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, S: CryptographicSuite> IntoIterator for &'a mut Proofs<S> {
    type IntoIter = std::slice::IterMut<'a, Proof<S>>;
    type Item = &'a mut Proof<S>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T: SerializeCryptographicSuite> Serialize for Proofs<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<'de, S: DeserializeCryptographicSuite<'de>> Deserialize<'de> for Proofs<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match OneOrMany::<Proof<S>>::deserialize(deserializer)? {
            OneOrMany::One(proof) => Ok(Self(vec![proof])),
            OneOrMany::Many(proofs) => Ok(Self(proofs)),
        }
    }
}
