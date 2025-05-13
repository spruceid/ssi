//! Verifiable Credentials Data Model v1.1 and v2.0 implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-model/>
//! See: <https://www.w3.org/TR/vc-data-model-2.0/>
mod id;
mod typed;

pub mod enveloped;
pub mod syntax;
pub mod v1;
pub mod v2;

pub use id::*;
pub use syntax::{AnyJsonCredential, AnyJsonPresentation, AnySpecializedJsonCredential};
pub use typed::*;

pub const MEDIA_TYPE_VC: &str = "application/vc";

pub const MEDIA_TYPE_VP: &str = "application/vp";
