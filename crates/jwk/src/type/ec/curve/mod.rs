#[cfg(feature = "secp256k1")]
mod secp256k1;

#[cfg(feature = "secp256r1")]
mod p256;

#[cfg(feature = "secp384r1")]
mod p384;

#[cfg(feature = "bbs")]
pub mod bbs;

// TODO according to https://tools.ietf.org/id/draft-jones-webauthn-secp256k1-00.html#rfc.section.2 it should be P-256K?
pub const SECP_256K1: &str = "secp256k1";
pub const P256: &str = "P-256";
pub const P384: &str = "P-384";
