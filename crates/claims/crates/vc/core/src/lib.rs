//! Verifiable Credential Data Model implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
use iref::Iri;
pub mod datatype;
pub mod vocab;
mod data_model;
pub mod verification;
pub mod syntax;
mod serialization;

pub use data_model::*;

pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");