use core::fmt;
use linked_data::{
    rdf_types::{
        dataset::PatternMatchingDataset,
        interpretation::{ReverseIriInterpretation, ReverseLiteralInterpretation},
        vocabulary::{IriVocabularyMut, LiteralVocabulary},
        Interpretation, LiteralType, LiteralTypeRef, Vocabulary, RDF_LANG_STRING,
    },
    Context, FromLinkedDataError, LinkedDataDeserializeSubject, LinkedDataPredicateObjects,
    LinkedDataSubject, RdfLiteral,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, ops::Deref, str::FromStr};

pub use multibase::{Base, Error};

use crate::MULTIBASE;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Multibase(str);

impl Multibase {
    pub fn new(value: &str) -> &Self {
        unsafe { std::mem::transmute(value) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn decode(&self) -> Result<(Base, Vec<u8>), Error> {
        multibase::decode(self)
    }
}

impl AsRef<str> for Multibase {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Multibase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V> for Multibase
where
    V: IriVocabularyMut,
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{rdf_types::Term, CowRdfTerm, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Owned(Term::Literal(
            RdfLiteral::Any(
                self.0.to_owned(),
                LiteralType::Any(vocabulary.insert(MULTIBASE)),
            ),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for Multibase
where
    V: IriVocabularyMut,
{
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for Multibase {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct MultibaseBuf(String);

impl MultibaseBuf {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn encode(base: Base, input: impl AsRef<[u8]>) -> Self {
        Self(multibase::encode(base, input))
    }

    pub fn as_multibase(&self) -> &Multibase {
        Multibase::new(self.0.as_str())
    }
}

impl Borrow<str> for MultibaseBuf {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<Multibase> for MultibaseBuf {
    fn borrow(&self) -> &Multibase {
        self.as_multibase()
    }
}

impl FromStr for MultibaseBuf {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned())) // TODO actually parse
    }
}

impl AsRef<str> for MultibaseBuf {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for MultibaseBuf {
    type Target = Multibase;

    fn deref(&self) -> &Self::Target {
        self.as_multibase()
    }
}

impl fmt::Display for MultibaseBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V> for MultibaseBuf
where
    V: IriVocabularyMut,
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{rdf_types::Term, CowRdfTerm, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Owned(Term::Literal(
            RdfLiteral::Any(
                self.0.to_owned(),
                LiteralType::Any(vocabulary.insert(MULTIBASE)),
            ),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for MultibaseBuf
where
    V: IriVocabularyMut,
{
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for MultibaseBuf {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

impl<V: Vocabulary, I> LinkedDataDeserializeSubject<I, V> for MultibaseBuf
where
    V: LiteralVocabulary,
    I: ReverseIriInterpretation<Iri = V::Iri> + ReverseLiteralInterpretation<Literal = V::Literal>,
{
    fn deserialize_subject_in<D>(
        vocabulary: &V,
        interpretation: &I,
        _dataset: &D,
        _graph: Option<&I::Resource>,
        resource: &<I as Interpretation>::Resource,
        context: Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        D: PatternMatchingDataset<Resource = I::Resource>,
    {
        let mut literal_ty = None;
        for l in interpretation.literals_of(resource) {
            let l = vocabulary.literal(l).unwrap();
            match l.type_ {
                LiteralTypeRef::Any(ty_iri) => {
                    let ty_iri = vocabulary.iri(ty_iri).unwrap();
                    if ty_iri == MULTIBASE {
                        return match l.value.parse() {
                            Ok(value) => Ok(value),
                            Err(_) => Err(FromLinkedDataError::InvalidLiteral(
                                context.into_iris(vocabulary, interpretation),
                            )),
                        };
                    }

                    literal_ty = Some(ty_iri)
                }
                LiteralTypeRef::LangString(_) => literal_ty = Some(RDF_LANG_STRING),
            }
        }

        match literal_ty {
            Some(ty) => Err(FromLinkedDataError::LiteralTypeMismatch {
                context: context.into_iris(vocabulary, interpretation),
                expected: Some(MULTIBASE.to_owned()),
                found: ty.to_owned(),
            }),
            None => Err(FromLinkedDataError::ExpectedLiteral(
                context.into_iris(vocabulary, interpretation),
            )),
        }
    }
}
