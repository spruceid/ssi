//! Verifiable Credential Data Model implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
use iref::Iri;
mod data_model;
pub mod datatype;
mod serialization;
mod syntax;
pub mod verification;
pub mod vocab;

pub use data_model::*;
pub use syntax::*;
pub use verification::Claims;

pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");

pub const CREDENTIALS_V2_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/ns/credentials/v2");

pub trait RequiredContext {
    const CONTEXT_IRI: &'static Iri;
}

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
