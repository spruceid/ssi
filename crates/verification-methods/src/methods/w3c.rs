#[cfg(feature = "rsa")]
mod rsa_verification_key_2018;
#[cfg(feature = "rsa")]
pub use rsa_verification_key_2018::RsaVerificationKey2018;

#[cfg(feature = "ed25519")]
mod ed25519_verification_key_2018;
#[cfg(feature = "ed25519")]
pub use ed25519_verification_key_2018::Ed25519VerificationKey2018;

#[cfg(feature = "ed25519")]
mod ed25519_verification_key_2020;
#[cfg(feature = "ed25519")]
pub use ed25519_verification_key_2020::Ed25519VerificationKey2020;

#[cfg(feature = "secp256k1")]
pub mod ecdsa_secp_256k1_verification_key_2019;
#[cfg(feature = "secp256k1")]
pub use ecdsa_secp_256k1_verification_key_2019::EcdsaSecp256k1VerificationKey2019;

#[cfg(feature = "secp256k1")]
pub mod ecdsa_secp_256k1_recovery_method_2020;
#[cfg(feature = "secp256k1")]
pub use ecdsa_secp_256k1_recovery_method_2020::EcdsaSecp256k1RecoveryMethod2020;

#[cfg(feature = "secp256r1")]
mod ecdsa_secp_256r1_verification_key_2019;
#[cfg(feature = "secp256r1")]
pub use ecdsa_secp_256r1_verification_key_2019::EcdsaSecp256r1VerificationKey2019;

mod json_web_key_2020;
pub use json_web_key_2020::JsonWebKey2020;

pub mod multikey;
pub use multikey::Multikey;
