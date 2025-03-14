pub const ED25519: &str = "Ed25519";

#[cfg(feature = "ed25519")]
mod ed25519;

#[cfg(feature = "aleo")]
pub mod aleo;
