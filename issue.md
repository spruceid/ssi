# Issuer Onboarding: Generating a Verifiable Credential

## Overview

This document walks through how an **issuer** generates a signing key, creates a Verifiable Credential (VC), signs it with Data Integrity, and saves both the key and the VC to files. See `holder.md` for how to verify the VC.

## Prerequisites

- Rust installed (https://www.rust-lang.org/learn/get-started)
- Cargo, the Rust package manager
- Git installed

## Setup

Clone the repository and initialize submodules:
```bash
$ git clone https://github.com/spruceid/ssi.git
$ cd ssi
$ git submodule update --init
```

## Step-by-Step Walkthrough

### Step 1: Generate and Persist an Issuer Key

The issuer needs a persistent key pair so the same DID identity can be reused across issuances. The test loads an existing key from file, or generates a new P256 key and saves it:

```rust
use ssi::prelude::*;

let key_path = "issuer_key.jwk";

let key: JWK = match std::fs::read_to_string(key_path) {
    Ok(contents) => serde_json::from_str(&contents).expect("failed to parse key"),
    Err(_) => {
        let new_key = JWK::generate_p256();
        let key_json = serde_json::to_string_pretty(&new_key)
            .expect("failed to serialize key");
        std::fs::write(key_path, &key_json).expect("failed to save key");
        new_key
    }
};
```

The saved `issuer_key.jwk` file contains both the private and public key in JWK format. Keep this file secure — the private key is used for signing.

### Step 2: Create a DID from the Key

A DID:JWK encodes the public key directly in the DID URL, so anyone who sees the DID can resolve the public key without a separate exchange:

```rust
let did = DIDJWK::generate_url(&key.to_public());
```

### Step 3: Build and Sign the Credential

Define a credential subject type with `#[serde(rename)]` attributes for linked-data compatibility, then create and sign the VC:

```rust
use serde::{Deserialize, Serialize};
use ssi::claims::vc::syntax::NonEmptyVec;
use ssi::claims::vc::v1::JsonCredential;
use static_iref::uri;

#[derive(Serialize, Deserialize)]
struct CredentialSubject {
    #[serde(rename = "https://example.org/#name")]
    name: String,
    #[serde(rename = "https://example.org/#email")]
    email: String,
}

let credential = JsonCredential::<CredentialSubject>::new(
    Some(uri!("https://example.org/#CredentialId").to_owned()),
    did.as_uri().to_owned().into(), // issuer = the DID
    DateTime::now().into(),
    NonEmptyVec::new(CredentialSubject {
        name: "Alice Doe".to_string(),
        email: "alice.doe@example.com".to_string(),
    }),
);

let vm_resolver = DIDJWK.into_vm_resolver();
let signer = SingleSecretSigner::new(key.clone()).into_local();
let verification_method = did.into_iri().into();

let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
    .expect("could not find appropriate cryptosuite");

let vc = cryptosuite
    .sign(
        credential,
        &vm_resolver,
        &signer,
        ProofOptions::from_method(verification_method),
    )
    .await
    .expect("signature failed");
```

### Step 4: Save the Signed VC

```rust
let json = serde_json::to_string_pretty(&vc).expect("failed to serialize VC");
std::fs::write("verifiable_credential.json", json).expect("failed to write file");
```

### Step 5: Run It

The full working example is in `tests/issue.rs`:
```bash
$ cargo test --test issue
```

This produces two files:
- `issuer_key.jwk` — the issuer's key pair (reused on subsequent runs)
- `verifiable_credential.json` — the signed VC

Both file paths are configurable via environment variables:
```bash
$ ISSUER_KEY_PATH=my_key.jwk VC_PATH=my_vc.json cargo test --test issue
```

## Next Step

Hand the `verifiable_credential.json` file to a holder/verifier. See `holder.md` for how to verify it.
