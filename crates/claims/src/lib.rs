//! Verifiable Claims.
pub mod data_integrity;
mod protocol;
mod verification_method;

pub use protocol::*;
pub use verification_method::*;

pub use ssi_claims_core::*;
