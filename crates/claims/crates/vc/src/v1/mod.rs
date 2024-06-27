//! Verifiable Credentials Data Model v1.1
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
use iref::Iri;

pub mod data_integrity;
mod data_model;
mod jwt;
pub mod revocation;
pub mod syntax;

pub use data_model::*;
pub use jwt::*;
pub use syntax::{
    Context, JsonCredential, JsonCredentialTypes, JsonPresentation, JsonPresentationTypes,
    SpecializedJsonCredential,
};

use crate::syntax::RequiredContext;

/// JSON-LD context IRI.
pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");

/// JSON-LD context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V1;

impl RequiredContext for V1 {
    const CONTEXT_IRI: &'static Iri = CREDENTIALS_V1_CONTEXT_IRI;
}
