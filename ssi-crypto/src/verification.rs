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

    /// Key not found.
    #[error("unknown key")]
    UnknownKey,

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

    #[error("invalid verification method `{0}`")]
    InvalidVerificationMethod(IriBuf),

    /// Verifier internal error.
    #[error("internal error: {0}")]
    InternalError(Box<dyn Send + std::error::Error>),
}

impl From<std::convert::Infallible> for VerificationError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

/// Verification method signature type.
pub trait Signature {
    /// Reference to a signature.
    type Reference<'a>
    where
        Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_>;
}

impl Signature for Vec<u8> {
    type Reference<'a> = &'a [u8] where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }
}

/// Verification method.
pub trait VerificationMethod {
    type Signature: Signature;

    type Reference<'a>
    where
        Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_>;
}

/// Verifier.
#[async_trait]
pub trait Verifier<M: VerificationMethod>: Sync {
    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing_bytes`.
    async fn verify<'m: 'async_trait, 's: 'async_trait>(
        &self,
        method: M::Reference<'m>,
        proof_purpose: ProofPurpose,
        signing_bytes: &[u8],
        signature: <M::Signature as Signature>::Reference<'s>,
    ) -> Result<bool, VerificationError>
    where
        M: 'async_trait;
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