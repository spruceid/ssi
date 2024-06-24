//! # Decentralized Identifiers (DIDs)
//!
//! As specified by [Decentralized Identifiers (DIDs) v1.0 - Core architecture,
//! data model, and representations][did-core].
//!
//! [did-core]: https://www.w3.org/TR/did-core/
use iref::Iri;
use static_iref::iri;

mod did;
pub mod document;
pub mod http;
pub mod method_resolver;
pub mod registration;
pub mod resolution;

#[cfg(feature = "example")]
pub mod example;

pub use did::*;
pub use document::Document;
pub use method_resolver::VerificationMethodDIDResolver;
pub use resolution::{DIDMethodResolver, DIDResolver, StaticDIDResolver};

pub use ssi_json_ld;

/// URI [required](https://www.w3.org/TR/did-core/#production-0) as the first value of the `@context` property for a DID Document in JSON-LD representation.
pub const JSON_LD_CONTEXT_IRI: &Iri = iri!("https://www.w3.org/ns/did/v1");

/// DID Method type.
pub trait DIDMethod {
    /// Name of the method.
    const DID_METHOD_NAME: &'static str;
}

impl<'a, M: DIDMethod> DIDMethod for &'a M {
    const DID_METHOD_NAME: &'static str = M::DID_METHOD_NAME;
}
