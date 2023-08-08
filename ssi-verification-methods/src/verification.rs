use std::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign}, future::Future, pin::Pin,
    task
};

use iref::{Iri, IriBuf};
use pin_project::pin_project;
use static_iref::iri;

use crate::{SignatureAlgorithm, Referencable, ReferenceOrOwnedRef, ControllerProvider, VerificationMethodRef, EnsureAllowsVerificationMethod};

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

    /// The verification key is not the same as the signing key.
    #[error("key mismatch")]
    KeyMismatch,

    /// Key not found.
    #[error("unknown key")]
    UnknownKey,

    /// Missing public key.
    #[error("missing public key")]
    MissingPublicKey,

    /// Cryptographic key is not used correctly.
    #[error("invalid use of key with <{0}>")]
    InvalidKeyUse(ProofPurpose),

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

    #[error("missing verification method")]
    MissingVerificationMethod,

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

/// Verifier.
pub trait Verifier<M: Referencable>: Sync + ControllerProvider {
    /// Future returned by the `resolve_verification_method` method.
    type ResolveVerificationMethod<'a, 'm: 'a>: 'a + Future<Output = Result<M::Reference<'a>, VerificationError>> where Self: 'a, M: 'm;

    /// Resolve the verification method reference.
    fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        issuer: Option<Iri<'a>>,
        method: Option<ReferenceOrOwnedRef<'m, M>>
    ) -> Self::ResolveVerificationMethod<'a, 'm>;

    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing`.
    fn verify<'f, 'm, 's, A: SignatureAlgorithm<M>>(
        &'f self,
        algorithm: A,
        issuer: Option<Iri<'f>>,
        method_reference: Option<ReferenceOrOwnedRef<'m, M>>,
        proof_purpose: ProofPurpose,
        signing_bytes: &'f [u8],
        signature: <A::Signature as Referencable>::Reference<'s>,
    ) -> Verify<'f, 'm, 's, M, Self, A>
    where
        M: 'f + 'm + Referencable
    {
        let resolution = self.resolve_verification_method(issuer, method_reference);

        Verify {
            verifier: self,
            proof_purpose,
            data: Some(VerifyData {
                algorithm,
                signature,
                signing_bytes
            }),
            resolution,
            check_purpose: None
        }
    }
}

#[pin_project]
pub struct Verify<'f, 'm: 'f, 's: 'f, M: 'm + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>> {
    verifier: &'f V,

    proof_purpose: ProofPurpose,

    data: Option<VerifyData<'f, 's, A, A::Signature>>,

    #[pin]
    resolution: V::ResolveVerificationMethod<'f, 'm>,

    #[pin]
    check_purpose: Option<VerifyProofPurpose<'f, M, V>>
}

struct VerifyData<'f, 's: 'f, A, S: 's + Referencable> {
    algorithm: A,

    signature: S::Reference<'s>,

    signing_bytes: &'f [u8],
}

#[pin_project]
struct VerifyProofPurpose<'a, M: 'a + Referencable, V: ?Sized + ControllerProvider> {
    method: Option<M::Reference<'a>>,
    
    #[pin]
    inner: Option<EnsureAllowsVerificationMethod<'a, V>>,
}

impl<'f, 'm, 's, M: 'm + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>> Future for Verify<'f, 'm, 's, M, V, A>
where
    M::Reference<'f>: VerificationMethodRef<'f>
{
    type Output = Result<bool, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let mut this = self.project();
        
        if this.check_purpose.is_some() {
            let check_purpose = this.check_purpose.as_pin_mut().unwrap().project();
            
            match check_purpose.inner.as_pin_mut() {
                Some(inner) => {
                    inner.poll(cx).map(|check_result| {
                        check_result.and_then(|()| {
                            let data = this.data.take().unwrap();
                            data.algorithm.verify(
                                data.signature,
                                check_purpose.method.take().unwrap(),
                                data.signing_bytes
                            )
                        })
                    })
                }
                None => {
                    let data = this.data.take().unwrap();
                    task::Poll::Ready(data.algorithm.verify(
                        data.signature,
                        check_purpose.method.take().unwrap(),
                        data.signing_bytes
                    ))
                }
            }
        } else {
            match this.resolution.poll(cx) {
                task::Poll::Pending => task::Poll::Pending,
                task::Poll::Ready(Ok(method)) => {
                    let inner = method.controller().map(|controller| {
                        this.verifier.ensure_allows_verification_method(
                            controller,
                            method.id(),
                            *this.proof_purpose
                        )
                    });
                    
                    this.check_purpose.set(Some(VerifyProofPurpose {
                        method: Some(method),
                        inner
                    }));

                    task::Poll::Pending
                },
                task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e))
            }
        }       
    }
}

macro_rules! proof_purposes {
    ($($(#[$doc:meta])* $id:ident: $variant:ident = $iri:expr),*) => {
        /// Proof purposes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[derive(serde::Serialize, serde::Deserialize)]
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
    #[serde(rename = "assertionMethod")]
    assertion_method: Assertion = iri!("https://w3id.org/security#assertionMethod"),

    /// <https://w3id.org/security#authenticationMethod>
    #[serde(rename = "authenticationMethod")]
    authentication: Authentication = iri!("https://w3id.org/security#authenticationMethod"),

    /// <https://w3id.org/security#capabilityInvocationMethod>
    #[serde(rename = "capabilityInvocationMethod")]
    capability_invocation: CapabilityInvocation = iri!("https://w3id.org/security#capabilityInvocationMethod"),

    /// <https://w3id.org/security#capabilityDelegationMethod>
    #[serde(rename = "capabilityDelegationMethod")]
    capability_delegation: CapabilityDelegation = iri!("https://w3id.org/security#capabilityDelegationMethod"),

    /// <https://w3id.org/security#keyAgreementMethod>
    #[serde(rename = "keyAgreementMethod")]
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
