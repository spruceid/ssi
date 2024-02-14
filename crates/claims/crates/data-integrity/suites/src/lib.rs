//! Data Integrity Cryptographic Suites.

pub mod eip712;
mod signatures;
mod suites;

pub use signatures::*;
pub use suites::*;

#[doc(hidden)]
pub use ssi_rdf;

#[doc(hidden)]
pub use ssi_data_integrity_core;
