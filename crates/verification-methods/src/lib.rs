//! This library provides the implementation of common Data Integrity
//! verification methods such as [`Multikey`] or [`JsonWebKey2020`].
//!
//! [`Multikey`]: crate::Multikey
//! [`JsonWebKey2020`]: crate::JsonWebKey2020
pub use ssi_verification_methods_core::*;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek;

mod methods;

pub use methods::*;
