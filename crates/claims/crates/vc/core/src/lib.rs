//! Verifiable Credential Data Model implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>

use iref::Iri;
pub mod datatype;
pub mod vocab;

pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");
