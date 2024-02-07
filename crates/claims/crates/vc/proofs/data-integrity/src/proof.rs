use core::fmt;

use linked_data::{
    LinkedData, LinkedDataGraph, LinkedDataPredicateObjects, LinkedDataResource, LinkedDataSubject,
    RdfLiteralValue,
};

use iref::{Iri, IriBuf};
use json_ld::rdf::RDF_TYPE;
use rdf_types::{Interpretation, Vocabulary, VocabularyMut};
use ssi_security::CRYPTOSUITE;
use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput,
};

mod configuration;
mod untyped;

pub use configuration::*;
pub use untyped::*;

/// Any proof type.
pub struct AnyType {
    pub name: String,
    pub cryptographic_suite: Option<String>,
}

impl AnyType {
    pub fn new(name: String, cryptographic_suite: Option<String>) -> Self {
        Self {
            name,
            cryptographic_suite,
        }
    }
}

/// Prepared Data-Integrity Proof.
pub struct PreparedProof<T: CryptographicSuite> {
    /// Raw proof.
    proof: Proof<T>,

    /// Hashed credential/presentation value.
    hash: T::Hashed,
}

impl<T: CryptographicSuite> PreparedProof<T> {
    pub fn new(proof: Proof<T>, hash: T::Hashed) -> Self {
        Self { proof, hash }
    }

    pub fn proof(&self) -> &Proof<T> {
        &self.proof
    }

    pub fn hash(&self) -> &T::Hashed {
        &self.hash
    }
}

impl<S: CryptographicSuite> ssi_vc_core::verification::ProofType for Proof<S> {
    type Prepared = PreparedProof<S>;
}

impl<S: CryptographicSuite> ssi_vc_core::verification::UnprepareProof for PreparedProof<S> {
    type Unprepared = Proof<S>;

    fn unprepare(self) -> Self::Unprepared {
        self.proof
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofPreparationError {
    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
}

impl<T, E, S> ssi_vc_core::verification::PrepareWith<T, E> for Proof<S>
where
    S: CryptographicSuiteInput<T, E>,
{
    type Error = ProofPreparationError;

    /// Creates a new data integrity credential from the given input data.
    ///
    /// This will transform and hash the input data using the cryptographic
    /// suite's transformation and hashing algorithms.
    async fn prepare_with(
        self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error> {
        let params = self.untyped.configuration();
        let transformed = self.type_.transform(&value, environment, params).await?;
        let hashed = self.type_.hash(transformed, params)?;
        Ok(PreparedProof::new(self, hashed))
    }
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
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
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataResource<I, V>
    for Proof<T>
{
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        linked_data::ResourceInterpretation::Uninterpreted(None)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataResource<I, V>
    for PreparedProof<T>
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        self.proof.interpretation(vocabulary, interpretation)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_subject<S>(&self, mut serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        serializer.predicate(RDF_TYPE, self.type_.iri())?;

        if let Some(cryptosuite) = self.type_.cryptographic_suite() {
            serializer.predicate(CRYPTOSUITE, cryptosuite)?;
        }

        self.untyped.visit_subject(serializer)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V>
    for PreparedProof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.proof.visit_subject(serializer)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V>
    for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V>
    for PreparedProof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        self.proof.visit_objects(visitor)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V> for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        visitor.subject(self)?;
        visitor.end()
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V>
    for PreparedProof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit_graph<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        self.proof.visit_graph(visitor)
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedData<I, V> for Proof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        visitor.default_graph(self)?;
        visitor.end()
    }
}

impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedData<I, V> for PreparedProof<T>
where
    T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    T::Options: LinkedDataSubject<I, V>,
    T::Signature: LinkedDataSubject<I, V>,
    V: VocabularyMut,
    V::Value: RdfLiteralValue,
{
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        self.proof.visit(visitor)
    }
}

/// Proof type.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Type {
    #[serde(rename = "type")]
    pub type_: String,

    #[serde(
        rename = "cryptosuite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cryptosuite: Option<String>,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.type_.fmt(f)?;
        if let Some(c) = &self.cryptosuite {
            write!(f, " ({c})")?;
        }

        Ok(())
    }
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
