#[cfg(feature = "ed25519")]
mod ed25519_verification_key_2018;

#[cfg(feature = "ed25519")]
mod ed25519_verification_key_2020;

mod json_web_key_2020;
mod multikey;

#[cfg(feature = "ed25519")]
pub use ed25519_verification_key_2018::*;

#[cfg(feature = "ed25519")]
pub use ed25519_verification_key_2020::*;

pub use json_web_key_2020::*;
pub use multikey::*;
