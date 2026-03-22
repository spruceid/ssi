# Holder Onboarding: Verifying a Verifiable Credential

## Overview

This document walks through how a **holder** (or verifier) reads a signed Verifiable Credential (VC) from a JSON file and verifies its Data Integrity proof. This is the second half of the credential lifecycle — see `issue.md` for how to issue the VC.

## Prerequisites

- Rust installed (https://www.rust-lang.org/learn/get-started)
- Cargo, the Rust package manager
- Git installed
- A signed VC file (produced by the issuer — see `issue.md`)

## Setup

Clone the repository and initialize submodules (if not already done):
```bash
$ git clone https://github.com/spruceid/ssi.git
$ cd ssi
$ git submodule update --init
```

## Step-by-Step Walkthrough

### Step 1: Read the VC from a File

The holder receives the signed VC as a JSON file (e.g. `verifiable_credential.json`):

```rust
let vc_path = "verifiable_credential.json";
let vc_json = std::fs::read_to_string(vc_path)
    .expect("failed to read VC file");
```

### Step 2: Deserialize the VC

Parse the JSON into a generic signed credential type. `AnyDataIntegrity<AnyJsonCredential>` accepts any Data Integrity suite and any JSON credential shape:

```rust
use ssi::prelude::*;

let vc: AnyDataIntegrity<AnyJsonCredential> =
    serde_json::from_str(&vc_json).expect("failed to parse VC JSON");
```

### Step 3: Verify the Signature

With DID:JWK, the issuer's public key is embedded directly in the DID URL inside the VC's proof. The `DIDJWK` resolver extracts it automatically — **no separate key file or key exchange is needed**.

```rust
let vm_resolver = DIDJWK.into_vm_resolver();
let params = VerificationParameters::from_resolver(vm_resolver);

vc.verify(params)
    .await
    .expect("verification error")
    .unwrap();
```

If verification fails, `verify()` returns an error describing what went wrong (e.g. invalid signature, unresolvable DID, expired proof).

### Step 4: Run It

First, generate a VC if you don't have one:
```bash
$ cargo test --test issue
```

Then verify it:
```bash
$ cargo test --test holder
```

To verify a VC at a custom path:
```bash
$ VC_PATH=path/to/my_vc.json cargo test --test holder
```

## Why No Key File Is Needed

In other verification systems, the verifier needs the issuer's public key out-of-band. With **DID:JWK**, the public key is encoded in the DID URL itself (e.g. `did:jwk:eyJrdH...`). When the DIDJWK resolver sees this DID, it base64-decodes the JWK directly from the URL — no network request, no key file, no trust registry lookup.

This makes DID:JWK convenient for testing and self-contained demos. In production, issuers typically use DID methods that resolve via a network (e.g. `did:web`, `did:key`) and verifiers maintain a trust list of accepted issuer DIDs.

## Next Steps

- Try modifying the VC JSON file and re-running the holder test to see verification fail
- Look at `tests/issue.rs` to see how the issuer side works
- Explore other DID methods in `crates/dids/methods/`
