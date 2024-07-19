use iref::{Iri, IriBuf};
use linked_data::{
    FromLinkedDataError, LinkedDataDeserializeSubject, LinkedDataPredicateObjects,
    LinkedDataSubject, RdfLiteral,
};
use rdf_types::{
    dataset::PatternMatchingDataset,
    interpretation::{ReverseIriInterpretation, ReverseLiteralInterpretation},
    vocabulary::{IriVocabularyMut, LiteralVocabulary},
    Interpretation, LiteralType, LiteralTypeRef, Vocabulary, RDF_LANG_STRING,
};
use serde::{Deserialize, Serialize};
use ssi_claims_core::ProofPreparationError;
use static_iref::iri;
use std::{fmt, ops::Deref, str::FromStr};

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("missing `cryptosuite` parameter")]
pub struct MissingCryptosuite;

/// Proof type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    DataIntegrityProof(CryptosuiteString),
    Other(String),
}

impl Type {
    pub fn new(
        type_: String,
        cryptosuite: Option<CryptosuiteString>,
    ) -> Result<Self, MissingCryptosuite> {
        if type_ == "DataIntegrityProof" {
            cryptosuite
                .ok_or(MissingCryptosuite)
                .map(Self::DataIntegrityProof)
        } else {
            Ok(Self::Other(type_.to_owned()))
        }
    }

    pub fn as_ref(&self) -> TypeRef {
        match self {
            Self::DataIntegrityProof(c) => TypeRef::DataIntegrityProof(c),
            Self::Other(t) => TypeRef::Other(t),
        }
    }
}

impl TryFrom<CompactType> for Type {
    type Error = MissingCryptosuite;

    fn try_from(value: CompactType) -> Result<Self, MissingCryptosuite> {
        Self::new(value.name, value.cryptosuite)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataIntegrityProof(cryptosuite) => {
                write!(f, "DataIntegrityProof ({cryptosuite})")
            }
            Self::Other(name) => name.fmt(f),
        }
    }
}

impl<'a> PartialEq<TypeRef<'a>> for Type {
    fn eq(&self, other: &TypeRef<'a>) -> bool {
        match (self, other) {
            (Self::DataIntegrityProof(a), TypeRef::DataIntegrityProof(b)) => **a == **b,
            (Self::Other(a), TypeRef::Other(b)) => a == b,
            _ => false,
        }
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CompactType::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Proof type reference.
pub enum TypeRef<'a> {
    DataIntegrityProof(&'a CryptosuiteStr),
    Other(&'a str),
}

impl<'a> TypeRef<'a> {
    pub fn data_integrity_proof_cryptosuite(&self) -> Option<&'a str> {
        match self {
            Self::DataIntegrityProof(c) => Some(c),
            _ => None,
        }
    }
}

impl<'a> Serialize for TypeRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct JsonTypeRef<'a> {
            #[serde(rename = "type")]
            type_: &'a str,

            #[serde(skip_serializing_if = "Option::is_none")]
            cryptosuite: Option<&'a str>,
        }

        match self {
            Self::DataIntegrityProof(c) => JsonTypeRef {
                type_: "DataIntegrityProof",
                cryptosuite: Some(c),
            },
            Self::Other(type_) => JsonTypeRef {
                type_,
                cryptosuite: None,
            },
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CompactType {
    #[serde(rename = "type")]
    pub name: String,

    #[serde(
        rename = "cryptosuite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cryptosuite: Option<CryptosuiteString>,
}

/// Expanded proof type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpandedType {
    /// Proof type IRI.
    pub iri: IriBuf,

    /// Cryptographic suite.
    pub cryptosuite: Option<String>,
}

impl fmt::Display for ExpandedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.iri.fmt(f)?;
        if let Some(c) = &self.cryptosuite {
            write!(f, " ({c})")?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UnsupportedProofSuite {
    #[error("unsupported proof suite: {0}")]
    Compact(Type),

    #[error("unsupported proof suite: {0}")]
    Expanded(ExpandedType),
}

impl From<UnsupportedProofSuite> for ProofPreparationError {
    fn from(value: UnsupportedProofSuite) -> Self {
        Self::Proof(value.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid cryptosuite string `{0}`")]
pub struct InvalidCryptosuiteString<T = String>(pub T);

pub const CRYPTOSUITE_STRING: &Iri =
    iri!("https://www.w3.org/TR/vc-data-integrity/#cryptosuiteString");

/// Cryptographic suite identifier.
///
/// Must be an ASCII string.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptosuiteString>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct CryptosuiteStr(str);

impl CryptosuiteStr {
    pub fn validate(bytes: &[u8]) -> bool {
        bytes.iter().all(u8::is_ascii)
    }

    /// Converts the given string into a cryptographic suite identifier.
    pub fn new(s: &str) -> Result<&Self, InvalidCryptosuiteString<&str>> {
        if Self::validate(s.as_bytes()) {
            Ok(unsafe { Self::new_unchecked(s) })
        } else {
            Err(InvalidCryptosuiteString(s))
        }
    }

    /// Converts the given string into a cryptographic suite identifier without
    /// validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid cryptographic suite identifier.
    pub unsafe fn new_unchecked(s: &str) -> &Self {
        std::mem::transmute(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for CryptosuiteStr {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for CryptosuiteStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for CryptosuiteStr {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for CryptosuiteStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Owned cryptographic suite identifier.
///
/// Must be an ASCII string.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptosuiteString>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CryptosuiteString(String);

impl CryptosuiteString {
    /// Converts the given string into an owned cryptographic suite identifier.
    pub fn new(s: String) -> Result<Self, InvalidCryptosuiteString> {
        if CryptosuiteStr::validate(s.as_bytes()) {
            Ok(Self(s))
        } else {
            Err(InvalidCryptosuiteString(s))
        }
    }

    /// Converts the given string into an owned cryptographic suite identifier
    /// without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid cryptographic suite identifier.
    pub unsafe fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    pub fn as_cryptosuite_str(&self) -> &CryptosuiteStr {
        unsafe { CryptosuiteStr::new_unchecked(self.0.as_str()) }
    }
}

impl Deref for CryptosuiteString {
    type Target = CryptosuiteStr;

    fn deref(&self) -> &CryptosuiteStr {
        self.as_cryptosuite_str()
    }
}

impl AsRef<CryptosuiteStr> for CryptosuiteString {
    fn as_ref(&self) -> &CryptosuiteStr {
        self.as_cryptosuite_str()
    }
}

impl AsRef<str> for CryptosuiteString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for CryptosuiteString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq<CryptosuiteStr> for CryptosuiteString {
    fn eq(&self, other: &CryptosuiteStr) -> bool {
        self.as_cryptosuite_str() == other
    }
}

impl<'a> PartialEq<&'a CryptosuiteStr> for CryptosuiteString {
    fn eq(&self, other: &&'a CryptosuiteStr) -> bool {
        self.as_cryptosuite_str() == *other
    }
}

impl PartialEq<str> for CryptosuiteString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for CryptosuiteString {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl fmt::Display for CryptosuiteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for CryptosuiteString {
    type Err = InvalidCryptosuiteString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V> for CryptosuiteString
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
                LiteralType::Any(vocabulary.insert(CRYPTOSUITE_STRING)),
            ),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for CryptosuiteString
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

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for CryptosuiteString {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

impl<V: Vocabulary, I> LinkedDataDeserializeSubject<I, V> for CryptosuiteString
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
        context: linked_data::Context<I>,
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
                    if ty_iri == CRYPTOSUITE_STRING {
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
                expected: Some(CRYPTOSUITE_STRING.to_owned()),
                found: ty.to_owned(),
            }),
            None => Err(FromLinkedDataError::ExpectedLiteral(
                context.into_iris(vocabulary, interpretation),
            )),
        }
    }
}
