#[cfg(feature = "ed25519")]
mod ed25519_public_key_blake2b_digest_size20_base58_check_encoded_2021;

#[cfg(feature = "ed25519")]
pub use ed25519_public_key_blake2b_digest_size20_base58_check_encoded_2021::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

#[cfg(feature = "secp256r1")]
mod p256_public_key_blake2b_digest_size20_base58_check_encoded_2021;

#[cfg(feature = "secp256r1")]
pub use p256_public_key_blake2b_digest_size20_base58_check_encoded_2021::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

pub mod tezos_method_2021;
pub use tezos_method_2021::TezosMethod2021;
