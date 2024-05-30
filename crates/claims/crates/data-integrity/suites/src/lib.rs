//! Data Integrity Cryptographic Suites.
pub mod eip712;

mod suites;
#[allow(unused_imports)]
pub use suites::*;

#[doc(hidden)]
pub use ssi_rdf;

#[doc(hidden)]
pub use ssi_data_integrity_core;
