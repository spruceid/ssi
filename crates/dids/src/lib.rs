//! DID Methods.
//! 
//! This library provides an interface for DIDs and
//! implementations for various DID methods.

// Re-export core definitions.
pub use ssi_dids_core::*;

// Re-export DID methods implementations.
pub use did_ethr as ethr;
pub use did_ion as ion;
pub use did_jwk as jwk;
pub use did_method_key as key;
pub use did_pkh as pkh;
pub use did_tz as tz;
pub use did_web as web;