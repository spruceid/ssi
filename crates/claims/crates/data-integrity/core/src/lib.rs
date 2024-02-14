//! Data Integrity Proofs format for Verifiable Credentals.

mod decode;
mod proof;
pub mod signing;
pub mod suite;
pub mod verification;

pub use decode::*;
pub use proof::*;
pub use signing::sign;
pub use suite::{CryptographicSuite, CryptographicSuiteInput};

#[doc(hidden)]
pub use ssi_rdf;
