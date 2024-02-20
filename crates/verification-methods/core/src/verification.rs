use std::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
};

use iref::{Iri, IriBuf};
use static_iref::iri;

use crate::{InvalidVerificationMethod, VerificationMethodResolutionError};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid input data")]
    InvalidInputData,

    #[error("verification method resolution failed: {0}")]
    Resolution(#[from] VerificationMethodResolutionError),

    /// Invalid proof.
    #[error("invalid proof")]
    InvalidProof,

    #[error("invalid hash")]
    InvalidHash,

    // /// Unsupported key identifier.
    // #[error("unsupported key id `{0}`")]
    // UnsupportedKeyId(String),

    // /// Invalid key identifier.
    // #[error("invalid key id `{0}`")]
    // InvalidKeyId(String),
    /// Invalid key.
    #[error("invalid key")]
    InvalidKey,

    // /// The verification key is not the same as the signing key.
    // #[error("key mismatch")]
    // KeyMismatch,
    /// Key not found.
    #[error("unknown key")]
    UnknownKey,

    /// Missing public key.
    #[error("missing public key")]
    MissingPublicKey,

    /// More than one public key is provided.
    #[error("ambiguous public key")]
    AmbiguousPublicKey,

    /// Cryptographic key is not used correctly.
    #[error("invalid use of key with <{0}>")]
    InvalidKeyUse(ProofPurpose),

    #[error("invalid proof options")]
    InvalidProofOptions,

    #[error("missing signature")]
    MissingSignature,

    #[error("invalid signature")]
    InvalidSignature,

    /// Key controller was not found.
    #[error("key controller `{0}` not found")]
    KeyControllerNotFound(String),

    /// Key controller is invalid.
    #[error("invalid key controller")]
    InvalidKeyController,

    /// Unsupported controller scheme.
    #[error("unsupported key controller scheme `{0}`")]
    UnsupportedControllerScheme(String),

    // #[error("missing verification method")]
    // MissingVerificationMethod,
    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),

    /// Verifier internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<std::convert::Infallible> for VerificationError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

macro_rules! proof_purposes {
    ($($(#[$doc:meta])* $id:ident: $variant:ident = $iri:literal),*) => {
        /// Proof purposes.
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, linked_data::Serialize, linked_data::Deserialize)]
        #[derive(serde::Serialize, serde::Deserialize)]
        pub enum ProofPurpose {
            $(
                $(#[$doc])*
                #[ld($iri)]
                $variant
            ),*
        }

        impl ProofPurpose {
            pub fn from_iri(iri: &Iri) -> Option<Self> {
                $(
                    if iri == iri!($iri) {
                        return Some(Self::$variant)
                    }
                )*

                None
            }

            pub fn iri(&self) -> &Iri {
                match self {
                    $(
                        Self::$variant => iri!($iri)
                    ),*
                }
            }
        }

        impl BitOr<ProofPurpose> for ProofPurpose {
            type Output = ProofPurposes;

            fn bitor(self, other: Self) -> ProofPurposes {
                let result: ProofPurposes = self.into();
                result | other
            }
        }

        /// Set of proof purposes.
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct ProofPurposes {
            $(
                pub $id: bool
            ),*
        }

        impl ProofPurposes {
            pub fn none() -> Self {
                Self::default()
            }

            pub fn all() -> Self {
                Self {
                    $(
                        $id: true
                    ),*
                }
            }

            pub fn contains(&self, p: ProofPurpose) -> bool {
                match p {
                    $(
                        ProofPurpose::$variant => {
                            self.$id
                        }
                    )*
                }
            }

            pub fn contains_all(&self, p: Self) -> bool {
                *self & p == p
            }

            pub fn insert(&mut self, p: ProofPurpose) {
                match p {
                    $(
                        ProofPurpose::$variant => {
                            self.$id = true
                        }
                    )*
                }
            }

            pub fn remove(&mut self, p: ProofPurpose) {
                match p {
                    $(
                        ProofPurpose::$variant => {
                            self.$id = false
                        }
                    )*
                }
            }

            pub fn iter(&self) -> ProofPurposesIter {
                ProofPurposesIter {
                    $(
                        $id: self.$id
                    ),*
                }
            }
        }

        impl From<ProofPurpose> for ProofPurposes {
            fn from(p: ProofPurpose) -> Self {
                match p {
                    $(
                        ProofPurpose::$variant => {
                            Self {
                                $id: true,
                                ..Self::default()
                            }
                        }
                    )*
                }
            }
        }

        impl BitOr for ProofPurposes {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                Self {
                    $(
                        $id: self.$id | other.$id
                    ),*
                }
            }
        }

        impl BitOrAssign for ProofPurposes {
            fn bitor_assign(&mut self, other: Self) {
                $(
                    self.$id |= other.$id;
                )*
            }
        }

        impl BitOr<ProofPurpose> for ProofPurposes {
            type Output = Self;

            fn bitor(self, other: ProofPurpose) -> Self {
                match other {
                    $(
                        ProofPurpose::$variant => {
                            Self {
                                $id: true,
                                ..self
                            }
                        }
                    )*
                }
            }
        }

        impl BitOrAssign<ProofPurpose> for ProofPurposes {
            fn bitor_assign(&mut self, other: ProofPurpose) {
                match other {
                    $(
                        ProofPurpose::$variant => {
                            self.$id = true;
                        }
                    )*
                }
            }
        }

        impl BitAnd for ProofPurposes {
            type Output = Self;

            fn bitand(self, other: Self) -> Self {
                Self {
                    $(
                        $id: self.$id & other.$id
                    ),*
                }
            }
        }

        impl BitAndAssign for ProofPurposes {
            fn bitand_assign(&mut self, other: Self) {
                $(
                    self.$id &= other.$id;
                )*
            }
        }

        impl BitAnd<ProofPurpose> for ProofPurposes {
            type Output = Self;

            fn bitand(self, other: ProofPurpose) -> Self {
                match other {
                    $(
                        ProofPurpose::$variant => {
                            Self {
                                $id: true,
                                ..Self::default()
                            }
                        }
                    )*
                }
            }
        }

        impl BitAndAssign<ProofPurpose> for ProofPurposes {
            fn bitand_assign(&mut self, other: ProofPurpose) {
                match other {
                    $(
                        ProofPurpose::$variant => {
                            *self = Self {
                                $id: true,
                                ..Self::default()
                            };
                        }
                    )*
                }
            }
        }

        impl IntoIterator for ProofPurposes {
            type Item = ProofPurpose;
            type IntoIter = ProofPurposesIter;

            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct ProofPurposesIter {
            $(
                pub $id: bool
            ),*
        }

        impl Iterator for ProofPurposesIter {
            type Item = ProofPurpose;

            fn next(&mut self) -> Option<ProofPurpose> {
                $(
                    if self.$id {
                        self.$id = false;
                        return Some(ProofPurpose::$variant)
                    }
                )*

                None
            }
        }
    };
}

proof_purposes! {
    /// <https://w3id.org/security#assertionMethod>
    #[serde(rename = "assertionMethod")]
    #[default]
    assertion_method: Assertion = "https://w3id.org/security#assertionMethod",

    /// <https://w3id.org/security#authentication>
    #[serde(rename = "authentication")]
    authentication: Authentication = "https://w3id.org/security#authentication",

    /// <https://w3id.org/security#capabilityInvocation>
    #[serde(rename = "capabilityInvocation")]
    capability_invocation: CapabilityInvocation = "https://w3id.org/security#capabilityInvocation",

    /// <https://w3id.org/security#capabilityDelegation>
    #[serde(rename = "capabilityDelegation")]
    capability_delegation: CapabilityDelegation = "https://w3id.org/security#capabilityDelegation",

    /// <https://w3id.org/security#keyAgreement>
    #[serde(rename = "keyAgreement")]
    key_agreement: KeyAgreement = "https://w3id.org/security#keyAgreement"
}

impl fmt::Display for ProofPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.iri().fmt(f)
    }
}

pub struct UnknownProofPurpose(IriBuf);

impl TryFrom<IriBuf> for ProofPurpose {
    type Error = UnknownProofPurpose;

    fn try_from(value: IriBuf) -> Result<Self, Self::Error> {
        match Self::from_iri(value.as_iri()) {
            Some(p) => Ok(p),
            None => Err(UnknownProofPurpose(value)),
        }
    }
}
