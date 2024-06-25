//! Verifiable Credentials Data Model v2.0
//!
//! See: <https://www.w3.org/TR/vc-data-model-2.0/>
use iref::Iri;

use crate::syntax::RequiredContext;

mod data_model;
pub mod syntax;

pub use data_model::*;
pub use syntax::{Context, JsonCredential, JsonCredentialTypes, SpecializedJsonCredential};

/// JSON-LD context IRI.
pub const CREDENTIALS_V2_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/ns/credentials/v2");

/// JSON-LD context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V2;

impl RequiredContext for V2 {
    const CONTEXT_IRI: &'static Iri = CREDENTIALS_V2_CONTEXT_IRI;
}
