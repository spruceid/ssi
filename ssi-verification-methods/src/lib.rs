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

    // fn verify<'f, 'a: 'f, 's: 'f, S: ssi_crypto::Referencable>(
    //     &'a self,
    //     controllers: &'a impl ControllerProvider,
    //     proof_purpose: ssi_crypto::ProofPurpose,
    //     signing_bytes: &'a [u8],
    //     signature: S::Reference<'s>,
    // ) -> Pin<Box<dyn 'f + Send + Future<Output = Result<bool, ssi_crypto::VerificationError>>>>
    // where
    //     Self::Reference<'a>: Send + VerificationMethodRef<'a, Self, S>,
    //     S::Reference<'s>: Send,
    // {
    //     let r = self.as_reference();
    //     r.verify(
    //         controllers,
    //         proof_purpose,
    //         signing_bytes,
    //         signature,
    //     )
    // }
}

pub trait TypedVerificationMethod: VerificationMethod {
    fn expected_type() -> Option<ExpectedType>;

    /// Returns the name of the verification method's type.
    fn type_(&self) -> &str;
}

pub trait VerificationMethodRef<'m> {
    /// Identifier of the verification method.
    fn id(&self) -> &'m Iri;

    /// Returns the IRI of the verification method controller.
    fn controller(&self) -> Option<&'m Iri>; // Should be an URI.
}

impl<'m, M: VerificationMethod> VerificationMethodRef<'m> for &'m M {
    fn id(&self) -> &'m Iri {
        M::id(self)
    }

    fn controller(&self) -> Option<&'m Iri> {
        M::controller(self)
    }
}

impl<'m, M: VerificationMethod> Cow<'m, M>
where
    M::Reference<'m>: VerificationMethodRef<'m>,
{
    fn id<'a>(&'a self) -> &'a Iri {
        match self {
            Self::Owned(m) => m.id(),
            Self::Borrowed(b) => b.id(),
        }
    }

    fn controller<'a>(&'a self) -> Option<&'a Iri> {
        match self {
            Self::Owned(m) => m.controller(),
            Self::Borrowed(b) => b.controller(),
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
#[error("invalid verification method `{0}`")]
pub struct InvalidVerificationMethod(pub IriBuf);

impl From<InvalidVerificationMethod> for VerificationError {
    fn from(value: InvalidVerificationMethod) -> Self {
        Self::InvalidVerificationMethod(value.0)
    }
}

impl From<InvalidVerificationMethod> for SignatureError {
    fn from(value: InvalidVerificationMethod) -> Self {
        Self::InvalidVerificationMethod(value.0)
    }
}
