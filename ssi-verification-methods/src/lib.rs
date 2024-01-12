//! This library provides the implementation of common Data Integrity
//! verification methods such as [`Multikey`] or [`JsonWebKey2020`].
//! It is separated from the Data Integrity library ([`ssi-ldp`]) to allow
//! verification methods providers (such as [`ssi-dids`]) to reason about
//! verification methods without Data Integrity.
//!
//! [`Multikey`]: crate::Multikey
//! [`JsonWebKey2020`]: crate::JsonWebKey2020
//! [`ssi-ldp`]: <https://github.com/spruceid/ssi/tree/main/ssi-ldp>
//! [`ssi-dids`]: <https://github.com/spruceid/ssi/tree/main/ssi-dids>
use iref::{Iri, IriBuf};
use ssi_crypto::{MessageSignatureError, MessageSigner, SignatureProtocol};
use static_iref::iri;

mod controller;
mod methods;
mod reference;
pub mod signature;
pub mod verification;

pub use controller::*;
pub use methods::*;
pub use reference::*;
pub use signature::*;
pub use verification::*;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek;

/// Export some JSON-LD traits.
///
/// This module should be a crate reexport in the future.
pub mod json_ld;

/// IRI of the RDF property associated to the `controller` term found in a
/// verification method.
pub const CONTROLLER_IRI: &Iri = iri!("https://w3id.org/security#controller");

/// Expected verification method type.
#[derive(Debug, Clone)]
pub enum ExpectedType {
    One(String),
    Many(Vec<String>),
}

impl From<String> for ExpectedType {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

pub enum Cow<'a, T: 'a + Referencable> {
    Borrowed(T::Reference<'a>),
    Owned(T),
}

impl<'a, T: 'a + Referencable> Cow<'a, T> {
    pub fn as_reference<'b>(&'b self) -> T::Reference<'b>
    where
        'a: 'b,
    {
        match self {
            Self::Borrowed(b) => T::apply_covariance(*b),
            Self::Owned(m) => m.as_reference(),
        }
    }
}

pub trait Referencable {
    type Reference<'a>: Copy
    where
        Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_>;

    fn apply_covariance<'big: 'small, 'small>(r: Self::Reference<'big>) -> Self::Reference<'small>
    where
        Self: 'big;
}

#[macro_export]
macro_rules! covariance_rule {
    () => {
        fn apply_covariance<'big: 'small, 'small>(
            r: <Self as $crate::Referencable>::Reference<'big>,
        ) -> <Self as $crate::Referencable>::Reference<'small>
        where
            Self: 'big,
        {
            r
        }
    };
}

impl Referencable for () {
    type Reference<'a> = ();

    fn as_reference(&self) -> Self::Reference<'_> {
        *self
    }

    covariance_rule!();
}

impl<'t, T> Referencable for &'t T {
    type Reference<'a> = &'t T where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl Referencable for Vec<u8> {
    type Reference<'a> = &'a [u8] where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

/// Verification method.
pub trait VerificationMethod: Referencable {
    /// Identifier of the verification method.
    fn id(&self) -> &Iri;

    /// Returns the IRI of the verification method controller.
    fn controller(&self) -> Option<&Iri>; // Should be an URI.

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri;

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri>;
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationMethodResolutionError {
    #[error("unknown key")]
    UnknownKey,

    /// Invalid key identifier.
    #[error("invalid key id `{0}`")]
    InvalidKeyId(String),

    /// Unsupported key identifier.
    #[error("unsupported key id `{0}`")]
    UnsupportedKeyId(String),

    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),

    /// Verifier internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

pub trait VerificationMethodResolver<M: Referencable> {
    /// Resolve the verification method reference.
    #[allow(async_fn_in_trait)]
    async fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Result<Cow<'a, M>, VerificationMethodResolutionError>;
}

impl<'t, M: Referencable, T: VerificationMethodResolver<M>> VerificationMethodResolver<M>
    for &'t T
{
    async fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Result<Cow<'a, M>, VerificationMethodResolutionError> {
        T::resolve_verification_method(self, issuer, method).await
    }
}

pub trait SigningMethod<S, A: Copy>: VerificationMethod + Referencable {
    fn sign(
        &self,
        secret: &S,
        algorithm: A,
        protocol: impl SignatureProtocol<A>,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Self::sign_ref(self.as_reference(), secret, algorithm, protocol, bytes)
    }

    fn sign_ref(
        this: Self::Reference<'_>,
        secret: &S,
        algorithm: A,
        protocol: impl SignatureProtocol<A>,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let prepared_bytes = protocol.prepare_message(bytes);
        let signed_bytes = Self::sign_bytes_ref(this, secret, algorithm, &prepared_bytes)?;
        protocol.encode_signature(algorithm, signed_bytes)
    }

    fn sign_bytes(
        &self,
        secret: &S,
        algorithm: A,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Self::sign_bytes_ref(self.as_reference(), secret, algorithm, bytes)
    }

    fn sign_bytes_ref(
        this: Self::Reference<'_>,
        secret: &S,
        algorithm: A,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError>;
}

pub struct MethodWithSecret<'m, 's, M: 'm + Referencable, S> {
    pub method: M::Reference<'m>,
    pub secret: &'s S,
}

impl<'m, 's, M: 'm + Referencable, S> MethodWithSecret<'m, 's, M, S> {
    pub fn new(method: M::Reference<'m>, secret: &'s S) -> Self {
        Self { method, secret }
    }
}

impl<'m, 's, A: Copy, P: SignatureProtocol<A>, M: 'm + Referencable + SigningMethod<S, A>, S>
    MessageSigner<A, P> for MethodWithSecret<'m, 's, M, S>
{
    async fn sign(
        self,
        algorithm: A,
        protocol: P,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        M::sign_ref(self.method, self.secret, algorithm, protocol, message)
    }
}

pub trait TypedVerificationMethod: VerificationMethod {
    fn expected_type() -> Option<ExpectedType>;

    fn type_match(ty: &str) -> bool;

    /// Returns the name of the verification method's type.
    fn type_(&self) -> &str;

    fn ref_type<'a>(r: Self::Reference<'a>) -> &'a str;
}

// pub trait VerificationMethodRef<'m> {
//     /// Identifier of the verification method.
//     fn id(&self) -> &'m Iri;

//     /// Returns the IRI of the verification method controller.
//     fn controller(&self) -> Option<&'m Iri>; // Should be an URI.
// }

// impl<'m, M: VerificationMethod> VerificationMethodRef<'m> for &'m M {
//     fn id(&self) -> &'m Iri {
//         M::id(self)
//     }

//     fn controller(&self) -> Option<&'m Iri> {
//         M::controller(self)
//     }
// }

impl<'m, M: VerificationMethod> Cow<'m, M> {
    fn id<'a>(&'a self) -> &'a Iri {
        match self {
            Self::Owned(m) => m.id(),
            Self::Borrowed(b) => M::ref_id(*b),
        }
    }

    fn controller<'a>(&'a self) -> Option<&'a Iri> {
        match self {
            Self::Owned(m) => m.controller(),
            Self::Borrowed(b) => M::ref_controller(*b),
        }
    }
}

pub trait LinkedDataVerificationMethod {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object;
}

impl<'a, T: LinkedDataVerificationMethod> LinkedDataVerificationMethod for &'a T {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        T::quads(*self, quads)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidVerificationMethod {
    #[error("invalid verification method type IRI `{0}`")]
    InvalidTypeIri(IriBuf),

    #[error("invalid verification method type name `{0}`")]
    InvalidTypeName(String),

    #[error("missing verification method required property `{0}`")]
    MissingProperty(String),

    #[error("invalid verification method property `{0}`")]
    InvalidProperty(String),

    #[error("ambiguous public key")]
    AmbiguousPublicKey,

    #[error("unsupported method type")]
    UnsupportedMethodType,
}

impl InvalidVerificationMethod {
    pub fn invalid_type_iri(iri: &Iri) -> Self {
        Self::InvalidTypeIri(iri.to_owned())
    }

    pub fn invalid_type_name(name: &str) -> Self {
        Self::InvalidTypeName(name.to_owned())
    }

    pub fn missing_property(name: &str) -> Self {
        Self::MissingProperty(name.to_owned())
    }

    pub fn invalid_property(name: &str) -> Self {
        Self::InvalidProperty(name.to_owned())
    }
}
