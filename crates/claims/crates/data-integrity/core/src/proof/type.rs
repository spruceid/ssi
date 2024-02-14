use iref::IriBuf;
use std::fmt;

/// Proof type.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Type {
    #[serde(rename = "type")]
    pub name: String,

    #[serde(
        rename = "cryptosuite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cryptosuite: Option<String>,
}

impl Type {
    pub fn new(name: String, cryptosuite: Option<String>) -> Self {
        Self { name, cryptosuite }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)?;
        if let Some(c) = &self.cryptosuite {
            write!(f, " ({c})")?;
        }

        Ok(())
    }
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
