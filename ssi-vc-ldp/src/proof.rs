use linked_data::{
    LinkedDataPredicateObjects, LinkedDataResource, LinkedDataSubject, RdfLiteralValue,
};

use iref::{Iri, IriBuf};
use json_ld::rdf::RDF_TYPE;
use rdf_types::{Interpretation, Vocabulary, VocabularyMut};
use ssi_security::CRYPTOSUITE;
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

use crate::CryptographicSuite;

mod configuration;
mod untyped;

pub use configuration::*;
pub use untyped::*;

/// Any proof type.
pub struct AnyType {
    pub iri: IriBuf,
    pub cryptographic_suite: Option<String>,
}

impl AnyType {
    pub fn new(iri: IriBuf, cryptographic_suite: Option<String>) -> Self {
        Self {
            iri,
            cryptographic_suite,
        }
    }
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
#[derive(Debug, Clone)]
pub struct Proof<T: CryptographicSuite> {
    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    type_: T,

    /// Untyped proof.
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
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataSubject<V, I> for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<V, I>,
    T::Options: LinkedDataSubject<V, I>,
    T::Signature: LinkedDataSubject<V, I>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_subject<S>(&self, mut serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<V, I>,
    {
        serializer.predicate(RDF_TYPE, self.type_.iri())?;

        if let Some(cryptosuite) = self.type_.cryptographic_suite() {
            serializer.predicate(CRYPTOSUITE, cryptosuite)?;
        }

        self.untyped.visit_subject(serializer)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<V, I>
    for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<V, I>,
    T::Options: LinkedDataSubject<V, I>,
    T::Signature: LinkedDataSubject<V, I>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<V, I>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataResource<V, I>
    for Proof<T>
{
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<V, I> {
        linked_data::ResourceInterpretation::Uninterpreted(None)
    }
}

/// Proof type.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Type {
    #[serde(rename = "type")]
    type_: IriBuf,

    #[serde(
        rename = "cryptosuite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    cryptosuite: Option<String>,
}

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
            type_: &'a Iri,

            #[serde(rename = "cryptosuite", skip_serializing_if = "Option::is_none")]
            cryptosuite: Option<&'a str>,

            #[serde(flatten)]
            untyped: &'a UntypedProof<M, O, S>,
        }

        let typed = TypedProof {
            type_: self.type_.iri(),
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
