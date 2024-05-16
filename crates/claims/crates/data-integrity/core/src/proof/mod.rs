use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, DataIntegrity,
};
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{AttachProof, ProofPreparationError};
use ssi_core::{one_or_many::OneOrManyRef, OneOrMany, Referencable};
use ssi_json_ld::JsonLdNodeObject;
use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, ReferenceOrOwnedRef};
use std::collections::BTreeMap;
use std::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    ops::{Deref, DerefMut},
};

mod configuration;
mod prepared;
mod r#type;

pub use configuration::*;
pub use prepared::*;
pub use r#type::*;

/// Data Integrity Compact Proof.
#[derive(Educe)]
#[educe(Debug(bound(
    "S: Debug, S::VerificationMethod: Debug, S::Options: Debug, S::Signature: Debug"
)))]
#[educe(Clone(bound(
    "S: Clone, S::VerificationMethod: Clone, S::Options: Clone, S::Signature: Clone"
)))]
pub struct Proof<S: CryptographicSuite> {
    /// Proof context.
    pub context: Option<json_ld::syntax::Context>,

    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    pub type_: S,

    /// Date a creation of the proof.
    pub created: xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwned<S::VerificationMethod>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Specifies when the proof expires.
    pub expires: Option<xsd_types::DateTime>, // FIXME: should be `DateTimeStamp`

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
    pub domains: Vec<String>,

    /// Used to mitigate replay attacks.
    ///
    /// Used once for a particular domain and window of time. Examples of a
    /// challenge value include: `1235abcd6789`,
    /// `79d34551-ae81-44ae-823b-6dadbab9ebd4`, and `ruby`.
    pub challenge: Option<String>,

    /// Arbitrary string supplied by the proof creator.
    ///
    /// One use of this field is to increase privacy by decreasing linkability
    /// that is the result of deterministically generated signatures.
    pub nonce: Option<String>,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    pub options: S::Options,

    /// Proof signature.
    pub signature: S::Signature,

    /// Extra properties.
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<T: CryptographicSuite> Proof<T> {
    /// Creates a new proof.
    pub fn new(
        type_: T,
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<T::VerificationMethod>,
        proof_purpose: ProofPurpose,
        options: T::Options,
        signature: T::Signature,
    ) -> Self {
        Self {
            context: None,
            type_,
            created,
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
            options: self.options.as_reference(),
            signature: self.signature.as_reference(),
            extra_properties: &self.extra_properties,
        }
    }

    pub fn with_context(self, context: json_ld::syntax::Context) -> Self {
        Self {
            context: Some(context),
            ..self
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }

    pub fn configuration(&self) -> ProofConfigurationRef<T::VerificationMethod, T::Options> {
        ProofConfigurationRef {
            context: self.context.as_ref(),
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            options: self.options.as_reference(),
            extra_properties: &self.extra_properties,
        }
    }

    pub fn clone_configuration(&self) -> ProofConfiguration<T::VerificationMethod, T::Options>
    where
        T::VerificationMethod: Clone,
        T::Options: Clone,
    {
        ProofConfiguration {
            context: self.context.clone(),
            created: self.created,
            verification_method: self.verification_method.clone(),
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains.clone(),
            challenge: self.challenge.clone(),
            nonce: self.nonce.clone(),
            options: self.options.clone(),
            extra_properties: self.extra_properties.clone(),
        }
    }
}

impl<S: CryptographicSuite> ssi_claims_core::Proof for Proof<S> {
    type Prepared = PreparedProof<S>;
}

#[derive(Debug, thiserror::Error)]
pub enum LdProofPreparationError<E = ssi_json_ld::UnknownContext> {
    #[error("proof expansion failed: {0}")]
    ProofExpansion(#[from] ConfigurationExpansionError<E>),

    #[error(transparent)]
    UnsupportedProofSuite(#[from] UnsupportedProofSuite),

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
}

impl<T, E, S> ssi_claims_core::PrepareWith<T, E> for Proof<S>
where
    T: JsonLdNodeObject,
    S: CryptographicSuiteInput<T, E>,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    /// Creates a new data integrity credential from the given input data.
    ///
    /// This will transform and hash the input data using the cryptographic
    /// suite's transformation and hashing algorithms.
    async fn prepare_with(
        mut self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, ProofPreparationError> {
        let configuration = self.configuration();
        let ld_configuration = configuration
            .expand(
                value.json_ld_context().as_deref(),
                value.json_ld_type(),
                &self.type_,
                environment,
            )
            .await?;

        self.type_.refine_type(&ld_configuration.type_iri)?;

        let expanded_configuration = ld_configuration.with_configuration(self.configuration());
        let transformed = self
            .type_
            .transform(value, environment, expanded_configuration.borrow())
            .await?;
        let hashed = self.type_.hash(transformed, expanded_configuration)?;
        Ok(PreparedProof::new(self, hashed))
    }
}

impl<T, S: CryptographicSuite> AttachProof<T> for Proof<S> {
    type Attached = DataIntegrity<T, S>;

    fn attach_to(self, claims: T) -> Self::Attached {
        DataIntegrity::new(claims, self.into())
    }
}

// #[derive(linked_data::Deserialize)]
// struct ExpandedProofDocument<S: CryptographicSuite> {
//     #[ld("https://w3id.org/security#proof")]
//     proof: super::expanded::Proof<S>
// }

impl<T: CryptographicSuite> serde::Serialize for Proof<T>
where
    T::VerificationMethod: serde::Serialize,
    T::Options: serde::Serialize,
    T::Signature: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct TypedProof<'a, M, O, S> {
            #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
            context: Option<&'a json_ld::syntax::Context>,
            #[serde(rename = "type")]
            type_: &'a str,
            #[serde(rename = "cryptosuite", skip_serializing_if = "Option::is_none")]
            cryptosuite: Option<&'a str>,
            created: xsd_types::DateTime,
            verification_method: &'a ReferenceOrOwned<M>,
            proof_purpose: ProofPurpose,
            #[serde(skip_serializing_if = "Option::is_none")]
            expires: Option<&'a xsd_types::DateTime>,
            #[serde(rename = "domain", skip_serializing_if = "OneOrManyRef::is_empty")]
            domains: OneOrManyRef<'a, String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            challenge: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            nonce: Option<&'a str>,
            #[serde(flatten)]
            options: &'a O,
            #[serde(flatten)]
            signature: &'a S,
            #[serde(flatten)]
            extra_properties: &'a BTreeMap<String, json_syntax::Value>,
        }

        let typed = TypedProof {
            context: self.context.as_ref(),
            type_: self.type_.name(),
            cryptosuite: self.type_.cryptographic_suite(),
            created: self.created,
            verification_method: &self.verification_method,
            proof_purpose: self.proof_purpose,
            expires: self.expires.as_ref(),
            domains: OneOrManyRef::from_slice(&self.domains),
            challenge: self.challenge.as_deref(),
            nonce: self.nonce.as_deref(),
            options: &self.options,
            signature: &self.signature,
            extra_properties: &self.extra_properties,
        };

        typed.serialize(serializer)
    }
}

impl<'de, T: CryptographicSuite + TryFrom<Type>> serde::Deserialize<'de> for Proof<T>
where
    T::VerificationMethod: serde::Deserialize<'de>,
    T::Options: serde::Deserialize<'de>,
    T::Signature: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct TypedProof<M, O, S> {
            #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
            context: Option<json_ld::syntax::Context>,
            #[serde(flatten)]
            type_: Type,
            created: xsd_types::DateTime,
            verification_method: ReferenceOrOwned<M>,
            proof_purpose: ProofPurpose,
            #[serde(default)]
            expires: Option<xsd_types::DateTime>,
            #[serde(rename = "domain", default)]
            domains: OneOrMany<String>,
            #[serde(default)]
            challenge: Option<String>,
            #[serde(default)]
            nonce: Option<String>,
            #[serde(flatten)]
            options: O,
            #[serde(flatten)]
            signature: S,
            #[serde(flatten)]
            extra_properties: BTreeMap<String, json_syntax::Value>,
        }

        let typed = TypedProof::deserialize(deserializer)?;

        Ok(Self {
            context: typed.context,
            type_: typed
                .type_
                .try_into()
                .map_err(|_| <D::Error as serde::de::Error>::custom("invalid proof type"))?,
            created: typed.created,
            verification_method: typed.verification_method,
            proof_purpose: typed.proof_purpose,
            expires: typed.expires,
            domains: typed.domains.into_vec(),
            challenge: typed.challenge,
            nonce: typed.nonce,
            options: typed.options,
            signature: typed.signature,
            extra_properties: typed.extra_properties,
        })
    }
}

pub struct ProofRef<'a, S: CryptographicSuite> {
    /// Proof context.
    pub context: Option<&'a json_ld::syntax::Context>,

    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    pub type_: &'a S,

    /// Date a creation of the proof.
    pub created: xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwnedRef<'a, S::VerificationMethod>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    pub options: <S::Options as Referencable>::Reference<'a>,

    /// Proof signature.
    pub signature: <S::Signature as Referencable>::Reference<'a>,

    /// Extra properties.
    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}

/// Set of Data-Integrity proofs.
#[derive(Educe)]
#[educe(Debug(bound(
    "S: Debug, S::VerificationMethod: Debug, S::Options: Debug, S::Signature: Debug"
)))]
#[educe(Clone(bound(
    "S: Clone, S::VerificationMethod: Clone, S::Options: Clone, S::Signature: Clone"
)))]
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

impl<T: CryptographicSuite> Serialize for Proofs<T>
where
    T::VerificationMethod: Serialize,
    T::Options: Serialize,
    T::Signature: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<'de, S: CryptographicSuite + TryFrom<Type>> Deserialize<'de> for Proofs<S>
where
    S::VerificationMethod: serde::Deserialize<'de>,
    S::Options: serde::Deserialize<'de>,
    S::Signature: serde::Deserialize<'de>,
{
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

impl<S: CryptographicSuite> ssi_claims_core::Proof for Proofs<S> {
    type Prepared = PreparedProofs<S>;
}

impl<T, E, S> ssi_claims_core::PrepareWith<T, E> for Proofs<S>
where
    T: JsonLdNodeObject,
    S: CryptographicSuiteInput<T, E>,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    async fn prepare_with(
        self,
        claims: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, ProofPreparationError> {
        self.0
            .prepare_with(claims, environment)
            .await
            .map(PreparedProofs)
    }
}
