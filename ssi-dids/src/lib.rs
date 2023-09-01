//! # Decentralized Identifiers (DIDs)
//!
//! As specified by [Decentralized Identifiers (DIDs) v1.0 - Core architecture,
//! data model, and representations][did-core].
//!
//! [did-core]: https://www.w3.org/TR/did-core/
mod did;
pub mod document;
pub mod resolution;
pub mod verifier;

pub use did::*;
pub use document::Document;
pub use resolution::DIDResolver;
pub use verifier::DIDVerifier;
