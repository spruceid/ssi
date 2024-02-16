use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput,
};
use ssi_core::Referencable;
use ssi_json_ld::WithJsonLdContext;
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned, ReferenceOrOwnedRef};
use std::collections::BTreeMap;

mod configuration;
mod prepared;
mod r#type;

pub use configuration::*;
pub use prepared::*;
pub use r#type::*;

pub type Proofs<T> = Vec<Proof<T>>;

/// Data Integrity Compact Proof.
#[derive(Debug, Clone)]
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
            options: self.options.clone(),
            extra_properties: self.extra_properties.clone(),
        }
    }
}

impl<S: CryptographicSuite> ssi_claims_core::Proof for Proof<S> {
    type Prepared = PreparedProof<S>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProofPreparationError<E = ssi_json_ld::UnknownContext> {
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
    T: WithJsonLdContext,
    S: CryptographicSuiteInput<T, E>,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    type Error = ProofPreparationError<E::LoadError>;

    /// Creates a new data integrity credential from the given input data.
    ///
    /// This will transform and hash the input data using the cryptographic
    /// suite's transformation and hashing algorithms.
    async fn prepare_with(
        mut self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error> {
        let configuration = self.configuration();
        let ld_configuration = configuration
            .expand(value.json_ld_context().as_ref(), &self.type_, environment)
            .await?;

        self.type_.refine_type(&ld_configuration.type_iri)?;

        let expanded_configuration = ld_configuration.with_configuration(self.configuration());

        eprintln!("transformation");
        let transformed = self
            .type_
            .transform(value, environment, expanded_configuration.borrow())
            .await?;
        eprintln!("transformed");
        let hashed = self.type_.hash(transformed, expanded_configuration)?;
        eprintln!("hashed");
        Ok(PreparedProof::new(self, hashed))
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
