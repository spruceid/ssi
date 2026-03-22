# Issuer Onboarding: Issuing an SD-JWT Credential

## Overview

This document walks through how an **issuer** generates a signing key, creates an SD-JWT (Selective Disclosure JWT) credential, and saves both to files. The issuer decides which claims *can* be selectively disclosed — the holder later chooses which of those to actually reveal.

See `holder.md` for how the holder verifies and selectively presents the credential.

## Prerequisites

- Rust installed (https://www.rust-lang.org/learn/get-started)
- Cargo, the Rust package manager
- Git installed

## Setup

```bash
$ git clone https://github.com/spruceid/ssi.git
$ cd ssi
$ git submodule update --init
```

## Step-by-Step Walkthrough

### Step 1: Generate and Persist an Issuer Key

The issuer needs a persistent key pair so the same identity can be reused across issuances. The key is saved as a JWK file:

```rust
use ssi::prelude::*;

let key_path = "issuer_key.jwk";

let mut key: JWK = match std::fs::read_to_string(key_path) {
    Ok(contents) => serde_json::from_str(&contents).expect("failed to parse key"),
    Err(_) => {
        let new_key = JWK::generate_p256();
        let key_json = serde_json::to_string_pretty(&new_key)
            .expect("failed to serialize key");
        std::fs::write(key_path, &key_json).expect("failed to save key");
        new_key
    }
};

// Set the key ID to a DID:JWK URL so verifiers can resolve the public key
let did = DIDJWK::generate_url(&key.to_public());
key.key_id = Some(did.into());
```

The saved `issuer_key.jwk` contains both the private and public key. Keep it secure.

### Step 2: Define the Credential Claims

Define a claims type where concealable fields are `Option<T>`. When the holder hides a field, it deserializes as `None`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CredentialClaims {
    name: Option<String>,
    email: Option<String>,
}

// Required trait impls for SD-JWT claims
impl ssi::claims::jwt::ClaimSet for CredentialClaims {}
impl<E, P> ssi::claims::ValidateClaims<E, P> for CredentialClaims {}
```

### Step 3: Build and Sign the SD-JWT

Use `conceal_and_sign` to mark which claims can be selectively disclosed. The issuer conceals both `name` and `email` — the holder can later choose to reveal any combination:

```rust
use ssi::claims::sd_jwt::{ConcealJwtClaims, SdAlg};
use ssi::json_pointer;

let claims = JWTClaims::builder()
    .iss("https://example.org/issuer")
    .sub("alice")
    .with_private_claims(CredentialClaims {
        name: Some("Alice Doe".to_string()),
        email: Some("alice.doe@example.com".to_string()),
    })
    .unwrap();

// Conceal both fields — holder decides what to reveal
let sd_jwt = claims
    .conceal_and_sign(
        SdAlg::Sha256,
        &[json_pointer!("/name"), json_pointer!("/email")],
        &key,
    )
    .await
    .expect("SD-JWT signing failed");
```

The `json_pointer!` macro specifies JSON Pointer paths (RFC 6901) to the fields to conceal.

### Step 4: Save the SD-JWT

```rust
std::fs::write("credential.sd-jwt", sd_jwt.as_str())
    .expect("failed to write SD-JWT file");
```

### Step 5: Run It

```bash
$ cargo test --test issue
```

This produces:
- `issuer_key.jwk` — the issuer's key pair (reused on subsequent runs)
- `credential.sd-jwt` — the SD-JWT credential

Both paths are configurable:
```bash
$ ISSUER_KEY_PATH=my_key.jwk VC_PATH=my_credential.sd-jwt cargo test --test issue
```

## Next Step

Hand the `credential.sd-jwt` to a holder. See `holder.md` for how to selectively disclose and verify it.
