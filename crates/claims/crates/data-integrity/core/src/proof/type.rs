use iref::IriBuf;
use serde::{Deserialize, Serialize};
use ssi_claims_core::ProofPreparationError;
use std::fmt;

/// Proof type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    DataIntegrityProof(String),
    Other(String),
}

impl Type {
    pub fn as_ref(&self) -> TypeRef {
        match self {
            Self::DataIntegrityProof(c) => TypeRef::DataIntegrityProof(c),
            Self::Other(t) => TypeRef::Other(t),
        }
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
            (Self::DataIntegrityProof(a), TypeRef::DataIntegrityProof(b)) => a == b,
            (Self::Other(a), TypeRef::Other(b)) => a == b,
            _ => false,
        }
    }
}

/// Proof type reference.
pub enum TypeRef<'a> {
    DataIntegrityProof(&'a str),
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
    pub cryptosuite: Option<String>,
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
