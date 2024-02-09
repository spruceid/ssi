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
