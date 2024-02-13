use crate::CryptographicSuite;

mod configuration;
mod untyped;

pub use configuration::*;
use linked_data::LinkedDataResource;
use rdf_types::{Interpretation, Vocabulary};
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

// impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for Proof<T>
// where
//     T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
//     T::Options: LinkedDataSubject<I, V>,
//     T::Signature: LinkedDataSubject<I, V>,
//     V: VocabularyMut,
//     V::Value: RdfLiteralValue,
// {
//     fn visit_subject<S>(&self, mut serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::SubjectVisitor<I, V>,
//     {
//         serializer.predicate(RDF_TYPE, self.type_.iri())?;

//         if let Some(cryptosuite) = self.type_.cryptographic_suite() {
//             serializer.predicate(CRYPTOSUITE, cryptosuite)?;
//         }

//         self.untyped.visit_subject(serializer)
//     }
// }

// impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V>
//     for Proof<T>
// where
//     T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
//     T::Options: LinkedDataSubject<I, V>,
//     T::Signature: LinkedDataSubject<I, V>,
//     V: VocabularyMut,
//     V::Value: RdfLiteralValue,
// {
//     fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::PredicateObjectsVisitor<I, V>,
//     {
//         visitor.object(self)?;
//         visitor.end()
//     }
// }

// impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V> for Proof<T>
// where
//     T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
//     T::Options: LinkedDataSubject<I, V>,
//     T::Signature: LinkedDataSubject<I, V>,
//     V: VocabularyMut,
//     V::Value: RdfLiteralValue,
// {
//     fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::GraphVisitor<I, V>,
//     {
//         visitor.subject(self)?;
//         visitor.end()
//     }
// }

// impl<T: CryptographicSuite, V: Vocabulary, I: Interpretation> LinkedData<I, V> for Proof<T>
// where
//     T::VerificationMethod: LinkedDataPredicateObjects<I, V>,
//     T::Options: LinkedDataSubject<I, V>,
//     T::Signature: LinkedDataSubject<I, V>,
//     V: VocabularyMut,
//     V::Value: RdfLiteralValue,
// {
//     fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::Visitor<I, V>,
//     {
//         visitor.default_graph(self)?;
//         visitor.end()
//     }
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

// impl<'de, T: CryptographicSuite + TryFrom<Type>> serde::Deserialize<'de> for Proof<T>
// where
//     T::VerificationMethod: serde::Deserialize<'de>,
//     T::Options: serde::Deserialize<'de>,
//     T::Signature: serde::Deserialize<'de>,
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         #[derive(serde::Deserialize)]
//         struct TypedProof<M, O, S> {
//             #[serde(flatten)]
//             type_: Type,

//             #[serde(flatten)]
//             untyped: UntypedProof<M, O, S>,
//         }

//         let typed = TypedProof::deserialize(deserializer)?;

//         Ok(Self {
//             type_: typed
//                 .type_
//                 .try_into()
//                 .map_err(|_| <D::Error as serde::de::Error>::custom("invalid proof type"))?,
//             untyped: typed.untyped,
//         })
//     }
// }