//! Verifiable Credential Data Model implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
use iref::Iri;
mod data_integrity;
mod data_model;
pub mod datatype;
pub mod revocation;
mod syntax;
pub mod verification;
pub mod vocab;

pub use data_integrity::*;
pub use data_model::*;
pub use syntax::*;

pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");

pub const CREDENTIALS_V2_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/ns/credentials/v2");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V1;

impl RequiredContext for V1 {
    const CONTEXT_IRI: &'static Iri = CREDENTIALS_V1_CONTEXT_IRI;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V2;

impl RequiredContext for V2 {
    const CONTEXT_IRI: &'static Iri = CREDENTIALS_V2_CONTEXT_IRI;
}
