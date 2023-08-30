use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
    pin::Pin,
    task,
};

use iref::{Iri, IriBuf};
use linked_data::LinkedData;
use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use static_iref::iri;

use crate::{
    ControllerProvider, Cow, EnsureAllowsVerificationMethod, Referencable, ReferenceOrOwnedRef,
    SignatureAlgorithm, VerificationMethod, VerificationMethodRef,
};

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
    InternalError(String),
}

impl From<std::convert::Infallible> for VerificationError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

/// Verifier.
pub trait Verifier<M: Referencable>: ControllerProvider {
    /// Future returned by the `resolve_verification_method` method.
    type ResolveVerificationMethod<'a>: 'a + Future<Output = Result<Cow<'a, M>, VerificationError>>
    where
        Self: 'a,
        M: 'a;

    /// Resolve the verification method reference.
    fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Self::ResolveVerificationMethod<'a>;

    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing`.
    fn verify<'f, 'm: 'f, 's: 'f, A: SignatureAlgorithm<M>>(
        &'f self,
        algorithm: A,
        issuer: Option<&'f Iri>,
        method_reference: Option<ReferenceOrOwnedRef<'m, M>>,
        proof_purpose: ProofPurpose,
        signing_bytes: &'f [u8],
        signature: <A::Signature as Referencable>::Reference<'s>,
    ) -> Verify<'f, M, Self, A>
    where
        M: 'f + Referencable,
    {
        let resolution = self.resolve_verification_method(issuer, method_reference);

        Verify {
            verifier: self,
            proof_purpose,
            data: Some(VerifyData {
                algorithm,
                signature: <A::Signature as Referencable>::apply_covariance(signature),
                signing_bytes,
            }),
            resolution,
            check_purpose: None,
        }
    }
}

#[pin_project]
pub struct Verify<'f, M: 'f + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>>
{
    verifier: &'f V,

    proof_purpose: ProofPurpose,

    data: Option<VerifyData<'f, A, A::Signature>>,

    #[pin]
    resolution: V::ResolveVerificationMethod<'f>,

    #[pin]
    check_purpose: Option<SelfRefFuture<'f, UnboundedVerifyProofPurpose<M, V>>>,
}

struct UnboundedVerifyProofPurpose<M, C: ?Sized>(PhantomData<(M, C)>);

impl<'max, M: 'max + Referencable, C: 'max + ?Sized + ControllerProvider> UnboundedRefFuture<'max>
    for UnboundedVerifyProofPurpose<M, C>
{
    type Bound<'a> = VerifyProofPurpose<'a, M, C> where 'max: 'a;

    type Owned = Cow<'max, M>;

    type Output = Result<(), VerificationError>;
}

struct SetupVerifyProofPurpose<'a, V: ?Sized> {
    verifier: &'a V,
    proof_purpose: ProofPurpose,
}

impl<'max, M: 'max + Referencable, C: 'max + ?Sized + ControllerProvider>
    RefFutureBinder<'max, UnboundedVerifyProofPurpose<M, C>> for SetupVerifyProofPurpose<'max, C>
where
    M: VerificationMethod,
    M::Reference<'max>: VerificationMethodRef<'max>,
{
    fn bind<'a>(context: Self, method: &'a Cow<'max, M>) -> VerifyProofPurpose<'a, M, C>
    where
        'max: 'a,
    {
        match method.controller() {
            Some(controller_id) => {
                VerifyProofPurpose::Pending(context.verifier.ensure_allows_verification_method(
                    controller_id,
                    method.id(),
                    context.proof_purpose,
                ))
            }
            None => VerifyProofPurpose::Ok(PhantomData),
        }
    }
}

struct VerifyData<'f, A, S: 'f + Referencable> {
    algorithm: A,

    signature: S::Reference<'f>,

    signing_bytes: &'f [u8],
}

#[pin_project(project = VerifyProofPurposeProj)]
enum VerifyProofPurpose<'a, M: 'a + Referencable, V: 'a + ?Sized + ControllerProvider> {
    Ok(PhantomData<M>),
    Pending(#[pin] EnsureAllowsVerificationMethod<'a, V>),
}

impl<'a, M: 'a + Referencable, V: 'a + ?Sized + ControllerProvider> Future
    for VerifyProofPurpose<'a, M, V>
{
    type Output = Result<(), VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            VerifyProofPurposeProj::Ok(_) => task::Poll::Ready(Ok(())),
            VerifyProofPurposeProj::Pending(f) => f.poll(cx),
        }
    }
}

impl<'f, M: 'f + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>> Future
    for Verify<'f, M, V, A>
where
    M: VerificationMethod,
    M::Reference<'f>: VerificationMethodRef<'f>,
{
    type Output = Result<bool, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let mut this = self.project();

        if this.check_purpose.is_none() {
            match this.resolution.poll(cx) {
                task::Poll::Pending => return task::Poll::Pending,
                task::Poll::Ready(Ok(method)) => this.check_purpose.set(Some(SelfRefFuture::new(
                    method,
                    SetupVerifyProofPurpose {
                        verifier: *this.verifier,
                        proof_purpose: *this.proof_purpose,
                    },
                ))),
                task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e)),
            }
        }

        let check_purpose = this.check_purpose.as_pin_mut().unwrap();
        check_purpose.poll(cx).map(|(check_result, method)| {
            check_result.and_then(|()| {
                let data = this.data.take().unwrap();
                data.algorithm
                    .verify(data.signature, method.as_reference(), data.signing_bytes)
            })
        })
    }
}

macro_rules! proof_purposes {
    ($($(#[$doc:meta])* $id:ident: $variant:ident = $iri:literal),*) => {
        /// Proof purposes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, LinkedData)]
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
    assertion_method: Assertion = "https://w3id.org/security#assertionMethod",

    /// <https://w3id.org/security#authenticationMethod>
    #[serde(rename = "authenticationMethod")]
    authentication: Authentication = "https://w3id.org/security#authenticationMethod",

    /// <https://w3id.org/security#capabilityInvocationMethod>
    #[serde(rename = "capabilityInvocationMethod")]
    capability_invocation: CapabilityInvocation = "https://w3id.org/security#capabilityInvocationMethod",

    /// <https://w3id.org/security#capabilityDelegationMethod>
    #[serde(rename = "capabilityDelegationMethod")]
    capability_delegation: CapabilityDelegation = "https://w3id.org/security#capabilityDelegationMethod",

    /// <https://w3id.org/security#keyAgreementMethod>
    #[serde(rename = "keyAgreementMethod")]
    key_agreement: KeyAgreement = "https://w3id.org/security#keyAgreementMethod"
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
