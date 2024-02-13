use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

use super::PreparedProof;
use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, Type,
};
use educe::Educe;
use grdf::{BTreeDataset, Dataset, HashDataset};
use iref::IriBuf;
use linked_data::{
    LinkedDataDeserializePredicateObjects, LinkedDataDeserializeSubject, LinkedDataResource,
    LinkedDataSubject, RdfLiteralType, RdfLiteralValue,
};
use rdf_types::{
    BlankIdInterpretationMut, ExportedFromVocabulary, Id, InterpretationMut, IriInterpretation,
    IriInterpretationMut, IriVocabulary, IriVocabularyMut, Literal, LiteralInterpretationMut,
    LiteralVocabularyMut, ReverseBlankIdInterpretation, ReverseIriInterpretation,
    ReverseLiteralInterpretation, Term, VocabularyMut,
};
use ssi_core::Referencable;
use ssi_json_ld::{AnyJsonLdEnvironment, WithJsonLdContext};
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

mod configuration;
mod untyped;

pub use configuration::*;
pub use untyped::*;

/// Data Integrity Compact Proof.
#[derive(Debug, Clone, linked_data::Deserialize)]
pub struct Proof<T: CryptographicSuite> {
    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    #[ld(type)]
    type_: T,

    /// Untyped proof.
    #[ld(flatten)]
    untyped: UntypedProof<T::VerificationMethod, T::Options, T::Signature>,
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
            type_,
            untyped: UntypedProof::new(
                created,
                verification_method,
                proof_purpose,
                options,
                signature,
            ),
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }

    pub fn untyped(&self) -> &UntypedProof<T::VerificationMethod, T::Options, T::Signature> {
        &self.untyped
    }

    pub fn untyped_mut(
        &mut self,
    ) -> &mut UntypedProof<T::VerificationMethod, T::Options, T::Signature> {
        &mut self.untyped
    }

    pub fn configuration(&self) -> ProofConfigurationRef<T::VerificationMethod, T::Options> {
        self.untyped.configuration()
    }

    pub fn clone_configuration(&self) -> ProofConfiguration<T::VerificationMethod, T::Options>
    where
        T::VerificationMethod: Clone,
        T::Options: Clone,
    {
        self.untyped.clone_configuration()
    }

    pub fn signature(&self) -> &T::Signature {
        &self.untyped.signature
    }

    pub fn signature_mut(&mut self) -> &mut T::Signature {
        &mut self.untyped.signature
    }

    pub fn extra_properties(&self) -> &BTreeMap<String, json_syntax::Value> {
        &self.untyped.extra_properties
    }

    pub fn extra_properties_mut(&mut self) -> &BTreeMap<String, json_syntax::Value> {
        &mut self.untyped.extra_properties
    }
}

impl<S: CryptographicSuite> ssi_vc_core::verification::ProofType for Proof<S> {
    type Prepared = PreparedProof<S>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProofPreparationError<E = ssi_json_ld::UnknownContext> {
    #[error("proof expansion failed: {0}")]
    ProofExpansion(#[from] ConfigurationExpansionError<E>),

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
}

impl<T, E, S> ssi_vc_core::verification::PrepareWith<T, E> for Proof<S>
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
        self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error> {
        let configuration = self.untyped.configuration();
        let expanded_configuration = configuration
            .expand(value.json_ld_context().as_ref(), &self.type_, environment)
            .await?;

        let transformed = self
            .type_
            .transform(&value, environment, expanded_configuration.borrow())
            .await?;
        let hashed = self.type_.hash(transformed, expanded_configuration)?;
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
        struct TypedProof<'a, M, O, S> {
            #[serde(rename = "type")]
            type_: &'a str,

            #[serde(rename = "cryptosuite", skip_serializing_if = "Option::is_none")]
            cryptosuite: Option<&'a str>,

            #[serde(flatten)]
            untyped: &'a UntypedProof<M, O, S>,
        }

        let typed = TypedProof {
            type_: self.type_.name(),
            cryptosuite: self.type_.cryptographic_suite(),
            untyped: &self.untyped,
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
        struct TypedProof<M, O, S> {
            #[serde(flatten)]
            type_: Type,

            #[serde(flatten)]
            untyped: UntypedProof<M, O, S>,
        }

        let typed = TypedProof::deserialize(deserializer)?;

        Ok(Self {
            type_: typed
                .type_
                .try_into()
                .map_err(|_| <D::Error as serde::de::Error>::custom("invalid proof type"))?,
            untyped: typed.untyped,
        })
    }
}
