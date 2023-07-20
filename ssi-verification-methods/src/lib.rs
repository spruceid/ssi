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
use async_trait::async_trait;
use iref::Iri;
use rdf_types::VocabularyMut;
use static_iref::iri;
use std::hash::Hash;
use treeldr_rust_prelude::{AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

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
#[async_trait]
pub trait VerificationMethod {
    /// Identifier of the verification method.
    fn id(&self) -> Iri;

    /// Returns the name of the verification method's type.
    fn type_(&self) -> &str;

    /// Returns the IRI of the verification method controller.
    fn controller(&self) -> Iri; // Should be an URI.

    /// Verifies the given `signing_bytes` against the `signature`.
    async fn verify(
        &self,
        controllers: &impl ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, ssi_crypto::VerificationError>;
}

pub trait LinkedDataVerificationMethod {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object;
}

/// Verification methods.
pub enum Method {
    /// `Multikey`.
    Multikey(Mulitkey),

    /// `JsonWebKey2020`.
    JsonWebKey2020(JsonWebKey2020),

    /// Deprecated verification method for the `Ed25519Signature2020` suite.
    Ed25519VerificationKey2020(Ed25519VerificationKey2020),
}

impl LinkedDataVerificationMethod for Method {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Multikey(m) => m.quads(quads),
            Self::JsonWebKey2020(m) => m.quads(quads),
            Self::Ed25519VerificationKey2020(m) => m.quads(quads),
        }
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Method
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        match self {
            Self::Multikey(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta),
            Self::JsonWebKey2020(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta),
            Self::Ed25519VerificationKey2020(m) => {
                m.into_json_ld_object_meta(vocabulary, interpretation, meta)
            }
        }
    }
}

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Method
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn as_json_ld_object_meta(
        &self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        match self {
            Self::Multikey(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta),
            Self::JsonWebKey2020(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta),
            Self::Ed25519VerificationKey2020(m) => {
                m.as_json_ld_object_meta(vocabulary, interpretation, meta)
            }
        }
    }
}
