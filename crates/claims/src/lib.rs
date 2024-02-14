//! Verifiable Claims.
pub use ssi_claims_core::*;

/// JSON Web tokens (JWT).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7519>
pub use ssi_jwt as jwt;

/// W3C Verifiable Credentials (VC).
///
/// See: <https://www.w3.org/TR/vc-data-model>
pub use ssi_vc as vc;

/// Data-Integrity Proofs.
///
/// See: <https://www.w3.org/TR/vc-data-integrity>
pub use ssi_data_integrity as data_integrity;
