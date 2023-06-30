use std::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
};

use async_trait::async_trait;
use iref::{Iri, IriBuf};
use static_iref::iri;

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// Invalid proof.
    #[error("invalid proof")]
    InvalidProof,

    /// Unsupported key identifier.
    #[error("unsupported key id `{0}`")]
    UnsupportedKeyId(String),

    /// Invalid key identifier.
    #[error("invalid key id `{0}`")]
    InvalidKeyId(String),

    /// Invalid key.
    #[error("invalid key")]
    InvalidKey,

    /// Cryptographic key is not used correctly.
    #[error("invalid use of key with <{0}>")]
    InvalidKeyUse(ProofPurpose),

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

    /// Verifier internal error.
    #[error("internal error: {0}")]
    InternalError(Box<dyn Send + std::error::Error>),
}

/// Verifier.
#[async_trait]
pub trait Verifier<M>: Sync {
    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing_bytes`.
    async fn verify(
        &self,
        method: &M,
        proof_purpose: ProofPurpose,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerificationError>;
}

macro_rules! proof_purposes {
    ($($(#[$doc:meta])* $id:ident: $variant:ident = $iri:expr),*) => {
        /// Proof purposes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ProofPurpose {
            $(
                $(#[$doc])*
                $variant
            ),*
        }

        impl ProofPurpose {
            pub fn from_iri(iri: Iri) -> Option<Self> {
                $(
                    if iri == $iri {
                        return Some(Self::$variant)
                    }
                )*

                None
            }

            pub fn iri(&self) -> Iri<'static> {
                match self {
                    $(
                        Self::$variant => $iri
                    ),*
                }
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
    assertion_method: AssertionMethod = iri!("https://w3id.org/security#assertionMethod"),

    /// <https://w3id.org/security#authenticationMethod>
    authentication: Authentication = iri!("https://w3id.org/security#authenticationMethod"),

    /// <https://w3id.org/security#capabilityInvocationMethod>
    capability_invocation: CapabilityInvocation = iri!("https://w3id.org/security#capabilityInvocationMethod"),

    /// <https://w3id.org/security#capabilityDelegationMethod>
    capability_delegation: CapabilityDelegation = iri!("https://w3id.org/security#capabilityDelegationMethod"),

    /// <https://w3id.org/security#keyAgreementMethod>
    key_agreement: KeyAgreement = iri!("https://w3id.org/security#keyAgreementMethod")
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
