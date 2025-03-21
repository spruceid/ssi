# Cryptographic primitives for SSI

<!-- cargo-rdme start -->

This library provides a flexible dynamic interface for cryptographic
primitives on top of RustCrypto, where algorithms can be selected at run
time instead of compile time.

## Usage

```rust
use ssi_crypto::{AlgorithmInstance, KeyType, key::EcdsaKeyType};

/// Select a key type at run time.
let key_type = KeyType::Ecdsa(EcdsaKeyType::P256);

/// Generate a key of the given type.
let secret_key = key_type.generate()
    .expect("key generation failed");

/// Sign a message with the given algorithm.
let signature = secret_key.sign_bytes(
  AlgorithmInstance::Es256,
  b"message"
).expect("signature failed");

/// Get the public key.
let public_key = secret_key.to_public();

/// Verify the signature.
let verification = public_key.verify_bytes(
  AlgorithmInstance::Es256,
  b"message",
  &signature
).expect("verification failed");

assert!(verification.is_ok());
```

<!-- cargo-rdme end -->
