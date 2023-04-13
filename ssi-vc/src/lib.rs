//! Verifiable Credentials Data Model v1.1 implementation.
//! 
//! This library provides Rust types for the Verifiable Credentials Data Model.
//! Proof mechanism are defined as extensions of this data model.
//! The `ssi` library collection provides two proof mechanisms:
//!   - JSON Web Token, defined by the `ssi-jwt` library.
//!   - Data Integrity Proofs, defined by the `ssi-ldp` library.
use treeldr_rust_macros::tldr;

#[tldr("ssi-vc/src/schema.ttl")]
pub mod schema {
    #[prefix("https://treeldr.org/")]
    pub mod tldr {}

    #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
    pub mod rdfs {}

    #[prefix("http://www.w3.org/2001/XMLSchema#")]
    pub mod xsd {}

    #[prefix("https://w3.org/2018/credentials#")]
    pub mod cred {}
}

pub use schema::cred::*;
