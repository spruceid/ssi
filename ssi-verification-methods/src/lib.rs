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

mod controller;
mod methods;
mod reference;

pub use controller::*;
pub use methods::*;
pub use reference::*;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek;

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

/// Verification method.
pub trait VerificationMethod: ssi_crypto::VerificationMethod {
    /// Identifier of the verification method.
    fn id(&self) -> Iri;

    fn expected_type() -> Option<String>;

    /// Returns the name of the verification method's type.
    fn type_(&self) -> &str;

    /// Returns the IRI of the verification method controller.
    fn controller(&self) -> Iri; // Should be an URI.

    fn verify<'f, 'a: 'f, 's: 'f>(
        &'a self,
        controllers: &'a impl ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &'a [u8],
        signature: Self::SignatureRef<'s>,
    ) -> Pin<Box<dyn 'f + Send + Future<Output = Result<bool, ssi_crypto::VerificationError>>>>
    where
        Self::Reference<'a>: Send + VerificationMethodRef<'a, Self>,
        Self::SignatureRef<'s>: Send,
    {
        let r = self.as_reference();
        r.verify(controllers, proof_purpose, signing_bytes, signature)
    }
}

#[async_trait]
pub trait VerificationMethodRef<'a, M: 'a + ?Sized + VerificationMethod> {
    /// Verifies the given `signing_bytes` against the `signature`.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: M::SignatureRef<'s>,
    ) -> Result<bool, ssi_crypto::VerificationError>;
}

pub trait LinkedDataVerificationMethod {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object;
}

/// Signature value.
///
/// Modern cryptographic suites use the <https://w3id.org/security#proofValue>
/// property to provide the proof value using a multibase encoding.
/// However older cryptographic suites like `Ed25519Signature2018` may use
/// different encoding, like [Detached Json Web Signatures][1].
///
/// [1]: <https://tools.ietf.org/html/rfc7797>
pub enum Signature {
    /// Standard multibase encoding using the
    /// <https://w3id.org/security#proofValue> property.
    ///
    /// This this the official way of providing the proof value, but some older
    /// cryptographic suites like `Ed25519Signature2018` may use different
    /// means.
    Multibase(ssi_security::layout::Multibase),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#jws> property.
    ///
    /// See: <https://tools.ietf.org/html/rfc7797>
    JWS(ssi_jws::CompactJWSString),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#signatureValue> property.
    Base64(String),
}

impl Signature {
    pub fn as_multibase(&self) -> Option<&ssi_security::layout::Multibase> {
        match self {
            Self::Multibase(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_jws(&self) -> Option<&ssi_jws::CompactJWSStr> {
        match self {
            Self::JWS(jws) => Some(jws),
            _ => None,
        }
    }

    pub fn as_base64(&self) -> Option<&str> {
        match self {
            Self::Base64(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_multibase(self) -> Option<ssi_security::layout::Multibase> {
        match self {
            Self::Multibase(m) => Some(m),
            _ => None,
        }
    }

    pub fn into_jws(self) -> Option<ssi_jws::CompactJWSString> {
        match self {
            Self::JWS(jws) => Some(jws),
            _ => None,
        }
    }

    pub fn into_base64(self) -> Option<String> {
        match self {
            Self::Base64(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_reference(&self) -> SignatureRef {
        match self {
            Self::Multibase(m) => SignatureRef::Multibase(m),
            Self::JWS(jws) => SignatureRef::JWS(jws),
            Self::Base64(b) => SignatureRef::Base64(b),
        }
    }
}

impl From<ssi_security::layout::Multibase> for Signature {
    fn from(value: ssi_security::layout::Multibase) -> Self {
        Self::Multibase(value)
    }
}

impl From<ssi_jws::CompactJWSString> for Signature {
    fn from(value: ssi_jws::CompactJWSString) -> Self {
        Self::JWS(value)
    }
}

#[derive(Clone, Copy)]
pub enum SignatureRef<'a> {
    /// Standard multibase encoding using the
    /// <https://w3id.org/security#proofValue> property.
    ///
    /// This this the official way of providing the proof value, but some older
    /// cryptographic suites like `Ed25519Signature2018` may use different
    /// means.
    Multibase(&'a ssi_security::layout::Multibase),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#jws> property.
    ///
    /// See: <https://tools.ietf.org/html/rfc7797>
    JWS(&'a ssi_jws::CompactJWSStr),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#signatureValue> property.
    Base64(&'a str),
}

impl<'a> SignatureRef<'a> {
    pub fn as_multibase(self) -> Option<&'a ssi_security::layout::Multibase> {
        match self {
            Self::Multibase(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_jws(self) -> Option<&'a ssi_jws::CompactJWSStr> {
        match self {
            Self::JWS(jws) => Some(jws),
            _ => None,
        }
    }

    pub fn as_base64(self) -> Option<&'a str> {
        match self {
            Self::Base64(value) => Some(value),
            _ => None,
        }
    }
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
