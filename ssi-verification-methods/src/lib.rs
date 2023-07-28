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
use std::{future::Future, pin::Pin};

use async_trait::async_trait;
use iref::{Iri, IriBuf};
use static_iref::iri;

mod context;
mod controller;
mod methods;
mod reference;
pub mod signature;

pub use context::*;
pub use controller::*;
pub use methods::*;
pub use reference::*;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek;

/// Export some JSON-LD traits.
///
/// This module should be a crate reexport in the future.
pub mod json_ld;

pub use treeldr_rust_prelude;

/// IRI of the `rdf:type` property.
pub(crate) const RDF_TYPE_IRI: Iri<'static> =
    iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");

/// IRI of the `rdf:JSON` datatype.
pub(crate) const RDF_JSON: Iri<'static> = iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON");

/// IRI of the `xsd:string` datatype.
pub(crate) const XSD_STRING: Iri<'static> = iri!("http://www.w3.org/2001/XMLSchema#string");

/// IRI of the RDF property associated to the `controller` term found in a
/// verification method.
pub const CONTROLLER_IRI: Iri<'static> = iri!("https://w3id.org/security#controller");

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

/// Verification method.
pub trait VerificationMethod: ssi_crypto::VerificationMethod {
    /// Identifier of the verification method.
    fn id(&self) -> Iri;

    fn expected_type() -> Option<ExpectedType>;

    /// Returns the name of the verification method's type.
    fn type_(&self) -> &str;

    /// Returns the IRI of the verification method controller.
    fn controller(&self) -> Iri; // Should be an URI.

    fn verify<'f, 'a: 'f, 'c: 'f, 's: 'f>(
        &'a self,
        controllers: &'a impl ControllerProvider,
        context: <Self::ProofContext as ssi_crypto::Referencable>::Reference<'c>,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &'a [u8],
        signature: <Self::Signature as ssi_crypto::Referencable>::Reference<'s>,
    ) -> Pin<Box<dyn 'f + Send + Future<Output = Result<bool, ssi_crypto::VerificationError>>>>
    where
        Self::Reference<'a>: Send + VerificationMethodRef<'a, Self>,
        <Self::Signature as ssi_crypto::Referencable>::Reference<'s>: Send,
    {
        let r = self.as_reference();
        r.verify(
            controllers,
            context,
            proof_purpose,
            signing_bytes,
            signature,
        )
    }
}

#[async_trait]
pub trait VerificationMethodRef<'a, M: 'a + ?Sized + VerificationMethod> {
    /// Verifies the given `signing_bytes` against the `signature`.
    async fn verify<'c: 'async_trait, 's: 'async_trait>(
        self,
        controllers: &impl ControllerProvider,
        context: <M::ProofContext as ssi_crypto::Referencable>::Reference<'c>,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: <M::Signature as ssi_crypto::Referencable>::Reference<'s>,
    ) -> Result<bool, ssi_crypto::VerificationError>;
}

pub trait LinkedDataVerificationMethod {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object;
}

#[derive(Debug, thiserror::Error)]
#[error("invalid verification method `{0}`")]
pub struct InvalidVerificationMethod(pub IriBuf);

impl From<InvalidVerificationMethod> for ssi_crypto::VerificationError {
    fn from(value: InvalidVerificationMethod) -> Self {
        Self::InvalidVerificationMethod(value.0)
    }
}

pub trait TryFromVerificationMethod<M>: Sized {
    fn try_from_verification_method(method: M) -> Result<Self, InvalidVerificationMethod>;
}

pub trait TryIntoVerificationMethod<M>: Sized {
    fn try_into_verification_method(self) -> Result<M, InvalidVerificationMethod>;
}

impl<T, M: TryFromVerificationMethod<T>> TryIntoVerificationMethod<M> for T {
    fn try_into_verification_method(self) -> Result<M, InvalidVerificationMethod> {
        M::try_from_verification_method(self)
    }
}

pub trait IntoAnyVerificationMethod {
    type Output;

    fn into_any_verification_method(self) -> Self::Output;
}
