pub use ssi_data_integrity_core::*;
pub use ssi_data_integrity_suites as suites;

pub use ssi_di_sd_primitives::{JsonPointer, JsonPointerBuf};

mod any;
pub use any::*;

/// Any Data-Integrity proof known by this library.
pub type AnyProof = Proof<AnySuite>;

/// List of any Data-Integrity proof known by this library.
pub type AnyProofs = Proofs<AnySuite>;

/// Data-Integrity-secured claims with any cryptographic suite.
pub type AnyDataIntegrity<T = DataIntegrityDocument> = DataIntegrity<T, AnySuite>;
