# Holder Onboarding: Selective Disclosure Verification

## Overview

This document walks through how a **holder** takes an SD-JWT credential (issued per `issue.md`), selectively discloses only the `email` field (hiding `name`), and verifies it. This demonstrates the core value of SD-JWT: the holder controls which claims the verifier sees.

## Prerequisites

- Rust installed (https://www.rust-lang.org/learn/get-started)
- Cargo, the Rust package manager
- Git installed
- An SD-JWT credential file (produced by the issuer — see `issue.md`)

## Setup

```bash
$ git clone https://github.com/spruceid/ssi.git
$ cd ssi
$ git submodule update --init
```

## Step-by-Step Walkthrough

### Step 1: Read the SD-JWT

```rust
use ssi::claims::sd_jwt::SdJwtBuf;

let sd_jwt_str = std::fs::read_to_string("credential.sd-jwt")
    .expect("failed to read SD-JWT file");
let sd_jwt = SdJwtBuf::new(sd_jwt_str).expect("invalid SD-JWT format");
```

### Step 2: Decode, Reveal, and Verify

First decode the SD-JWT to see all claims. With DID:JWK, the issuer's public key is embedded in the JWT's `kid` header — no separate key file needed:

```rust
use ssi::prelude::*;

let vm_resolver = DIDJWK.into_vm_resolver::<AnyJwkMethod>();
let params = VerificationParameters::from_resolver(&vm_resolver);

let (mut revealed, verification) = sd_jwt
    .decode_reveal_verify::<CredentialClaims, _>(&params)
    .await
    .expect("SD-JWT decode/reveal failed");

assert_eq!(verification, Ok(()));
// revealed.claims().private => { name: Some("Alice Doe"), email: Some("alice.doe@example.com") }
```

### Step 3: Selectively Disclose Only Email

The holder calls `retain` with the JSON pointers of the fields to keep. Everything else is hidden:

```rust
use ssi::json_pointer;

// Only reveal email — hide name
revealed.retain(&[json_pointer!("/email")]);

// Re-encode the SD-JWT with only the selected disclosures
let selective_sd_jwt = revealed.into_encoded();
```

The re-encoded `selective_sd_jwt` can be sent to a verifier. It contains the same signed JWT but with fewer disclosure tokens — the verifier can only see the fields the holder chose to reveal.

### Step 4: Verifier Verifies the Selective SD-JWT

```rust
let (verified, verification) = selective_sd_jwt
    .decode_reveal_verify::<CredentialClaims, _>(params)
    .await
    .expect("selective SD-JWT verification failed");

assert_eq!(verification, Ok(()));

// Only email is visible — name is concealed
assert_eq!(verified.claims().private.name, None);
assert_eq!(
    verified.claims().private.email,
    Some("alice.doe@example.com".to_string())
);
```

### Step 5: Run It

First issue a credential (if you haven't already):
```bash
$ cargo test --test issue
```

Then run the holder test:
```bash
$ cargo test --test holder
```

To use a custom SD-JWT path:
```bash
$ VC_PATH=path/to/credential.sd-jwt cargo test --test holder
```

## How SD-JWT Selective Disclosure Works

| Step | Who | What happens |
|------|-----|-------------|
| 1. Issuance | Issuer | Marks claims as concealable via `conceal_and_sign`. Each concealed claim gets a random salt + hash in the JWT payload, and a disclosure token appended after the JWT. |
| 2. Full reveal | Holder | `decode_reveal_verify` decodes all disclosure tokens, matches them to hashes in the JWT, and reconstructs the full claims. |
| 3. Selective retain | Holder | `retain` drops disclosure tokens for fields the holder wants to hide. Without the token, the verifier can't reverse the hash. |
| 4. Verification | Verifier | `decode_reveal_verify` on the subset SD-JWT only sees fields whose disclosure tokens are present. Hidden fields deserialize as `None`. |

The JWT signature covers the hashes (not the raw values), so it remains valid regardless of which disclosures the holder includes.

## Key Types

- `SdJwtBuf` — an SD-JWT string (JWT + `~`-separated disclosure tokens)
- `RevealedSdJwt<T>` — decoded SD-JWT with revealed claims of type `T`
- `retain(&[json_pointer!(...)])` — keep only the specified disclosures
- `into_encoded()` — re-encode back to `SdJwtBuf` for transmission

## Next Steps

- Try revealing different combinations of fields (both, neither, just name)
- Look at `crates/claims/crates/sd-jwt/tests/full_pathway.rs` for more examples including nested claims and arrays
- Explore BBS+ (`bbs-2023`) for zero-knowledge selective disclosure with Data Integrity proofs
