//! Verifiable Credentials Data Model v1.1 and v2.0 implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
//! See: <https://www.w3.org/TR/vc-data-model-2.0/>
mod id;
pub use id::*;
mod typed;
pub use typed::*;

pub mod datatype;
pub mod enveloped;
pub mod syntax;
pub mod v1;
pub mod v2;

pub use syntax::{AnyJsonCredential, AnyJsonPresentation, AnySpecializedJsonCredential};
