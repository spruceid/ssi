//! W3C crypto suites.
//!
//! This module includes the definitions of many Data Integrity cryptographic
//! suites specified by the W3C organization.

pub mod ed25519_signature_2020;
// pub mod edssa_2022;
pub mod json_web_signature_2020;

pub use ed25519_signature_2020::Ed25519Signature2020;
// pub use edssa_2022:: EdSsa2022;
// pub use json_web_signature_2020
