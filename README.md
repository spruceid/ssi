[![](https://img.shields.io/github/actions/workflow/status/spruceid/ssi/build.yml?branch=main)](https://github.com/spruceid/ssi/actions?query=workflow%3Aci+branch%3Amain)
[![](https://img.shields.io/badge/Rust-v1.66.0-orange)](https://www.rust-lang.org/)
[![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE)
[![](https://img.shields.io/twitter/follow/spruceid?label=Follow&style=social)](https://twitter.com/spruceid)

# SSI

<!-- cargo-rdme start -->

The SSI library provides a simple and modular API to sign and verify claims
exchanged between applications using
[Decentralized Identifiers (DIDs)][dids]. SSI is embedded in the
cross-platform [`didkit`][didkit] library as a core dependency.

This library supports the two main families of verifiable claims:
- [JSON Web Tokens (JWT)][jwt] where claims are encoded into JSON and
  secured using [JSON Web Signatures][jws]; and
- [W3C's Verifiable Credentials (VCs)][vc-data-model], a
  [Linked-Data][linked-data]-based model where claims (VCs) can be
  interpreted as RDF datasets. VC supports multiple signature formats
  provided by SSI:
  - VC over JWT ([JWT-VC][jwt-vc]), a restricted form of JWT following the
    VC data model; or
  - [Data Integrity][data-integrity], encoding the claims and their proof
    in the same JSON-LD document using a wide variety of
    [*cryptographic suites*][cryptosuite].

[dids]: <https://www.w3.org/TR/did-core/>
[didkit]: <https://github.com/spruceid/didkit>
[vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
[linked-data]: <https://www.w3.org/DesignIssues/LinkedData.html>
[jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
[jws]: <https://www.rfc-editor.org/rfc/rfc7515>
[jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
[data-integrity]: <https://www.w3.org/TR/vc-data-integrity/>
[cryptosuite]: <https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite>

## Basic Usage

SSI provides various functions to parse, verify, create and sign various
kind of claims. This section shows how to use these functions in combination
with JSON Web Signatures (or Tokens) and Verifiable Credentials.

### Verification

The simplest type of claim to load and verify is probably JSON Web
Signatures (JWSs), often use to encode JSON Web Tokens (JWTs). To represent
such claims SSI provides the `CompactJWSString` type representing a JWS
in compact textual form. One can load a JWS using `from_string` and verify
it using `verify`.


```rust
use ssi::prelude::*;

// Load a JWT from the file system.
let jwt = CompactJWSString::from_string(
  std::fs::read_to_string("examples/files/claims.jwt")
  .expect("unable to load JWT")
).expect("invalid JWS");

// Setup a verification method resolver, in charge of retrieving the
// public key used to sign the JWT.
// Here we use the example `ExampleDIDResolver` resolver, enabled with the
// `example` feature.
let vm_resolver = ExampleDIDResolver::default().into_vm_resolver::<AnyJwkMethod>();

// Setup the verification parameters.
let params = VerificationParameters::from_resolver(vm_resolver);

// Verify the JWT.
assert!(jwt.verify(&params).await.expect("verification failed").is_ok())
```

#### Verifiable Credentials

Verifiable Credential are much more complex as they require interpreting
the input claims and proofs, such as Data-Integrity proofs as Linked-Data
using JSON-LD. This operation is highly configurable. SSI provide
functions exposing various levels of implementation details that you can
tweak as needed. The simplest of them is `any_credential_from_json_str`
that will simply load a VC from a string, assuming it is signed using
any Data-Integrity proof supported by SSI.


```rust
use ssi::prelude::*;

let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
  &std::fs::read_to_string("examples/files/vc.jsonld")
  .expect("unable to load VC")
).expect("invalid VC");

// Setup a verification method resolver, in charge of retrieving the
// public key used to sign the JWT.
let vm_resolver = ExampleDIDResolver::default().into_vm_resolver();

// Setup the verification parameters.
let params = VerificationParameters::from_resolver(vm_resolver);

assert!(vc.verify(&params).await.expect("verification failed").is_ok());
```

### Signature & Custom Claims

In the previous section we have seen how to load and verify arbitrary
claims. This section shows how to create and sign custom claims.
With SSI, any Rust type can serve as claims as long as it complies to
certain conditions such as implementing serialization/deserialization
functions using [`serde`](https://crates.io/crates/serde).
Don't forget to enable the `derive` feature for `serde`.

In the following example, we create a custom type `MyClaims` and sign it
as a JWT.

```rust
use serde::{Serialize, Deserialize};
use ssi::prelude::*;

// Defines the shape of our custom claims.
#[derive(Serialize, Deserialize)]
pub struct MyClaims {
  name: String,
  email: String
}

// Create JWT claims from our custom ("private") claims.
let claims = JWTClaims::from_private_claims(MyClaims {
  name: "John Smith".to_owned(),
  email: "john.smith@example.org".to_owned()
});

// Create a random signing key, and turn its public part into a DID URL.
let mut key = JWK::generate_p256(); // requires the `p256` feature.
let did = DIDJWK::generate_url(&key.to_public());
key.key_id = Some(did.into());

// Sign the claims.
let jwt = claims.sign(&key).await.expect("signature failed");

// Create a verification method resolver, which will be in charge of
// decoding the DID back into a public key.
let vm_resolver = DIDJWK.into_vm_resolver::<AnyJwkMethod>();

// Setup the verification parameters.
let params = VerificationParameters::from_resolver(vm_resolver);

// Verify the JWT.
assert!(jwt.verify(&params).await.expect("verification failed").is_ok());

// Print the JWT.
println!("{jwt}")
```

#### Verifiable Credential

We can use a similar technique to sign a VC with custom claims.
The `SpecializedJsonCredential` type provides a customizable
implementation of the VC data-model 1.1 where you can set the credential type
yourself.


```rust
use static_iref::uri;
use serde::{Serialize, Deserialize};
use ssi::prelude::*;

// Defines the shape of our custom claims.
#[derive(Serialize, Deserialize)]
pub struct MyCredentialSubject {
  #[serde(rename = "https://example.org/#name")]
  name: String,

  #[serde(rename = "https://example.org/#email")]
  email: String
}

let credential = ssi::claims::vc::v1::JsonCredential::<MyCredentialSubject>::new(
  Some(uri!("https://example.org/#CredentialId").to_owned()), // id
  uri!("https://example.org/#Issuer").to_owned().into(), // issuer
  DateTime::now(), // issuance date
  vec![MyCredentialSubject {
    name: "John Smith".to_owned(),
    email: "john.smith@example.org".to_owned()
  }]
);

// Create a random signing key, and turn its public part into a DID URL.
let key = JWK::generate_p256(); // requires the `p256` feature.
let did = DIDJWK::generate_url(&key.to_public());

// Create a verification method resolver, which will be in charge of
// decoding the DID back into a public key.
let vm_resolver = DIDJWK.into_vm_resolver();

// Create a signer from the secret key.
// Here we use the simple `SingleSecretSigner` signer type which always uses
// the same provided secret key to sign messages.
let signer = SingleSecretSigner::new(key.clone()).into_local();

// Turn the DID URL into a verification method reference.
let verification_method = did.into_iri().into();

// Automatically pick a suitable Data-Integrity signature suite for our key.
let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
  .expect("could not find appropriate cryptosuite");

let vc = cryptosuite.sign(
  credential,
  &vm_resolver,
  &signer,
  ProofOptions::from_method(verification_method)
).await.expect("signature failed");
```
 
It is critical that custom claims can be interpreted as Linked-Data. In
the above example this is done by specifying a serialization URL for each
field of `MyCredentialSubject`. This can also be done by creating a custom
JSON-LD context and embed it to `credential` using either
`SpecializedJsonCredential`'s `context` field or leveraging its context type
parameter.


## Data-Models

The examples above are using the VC data-model 1.1, but you ssi also has support for:
- `VC data-model 2.0`
- `A wrapper type to accept both`


## Features

<!-- cargo-rdme end -->

## Security Audits

ssi has undergone the following security reviews:
- [March 14th, 2022 - Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/SpruceID.pdf) | [Summary of Findings](https://blog.spruceid.com/spruce-completes-first-security-audit-from-trail-of-bits/)

## Testing

Testing SSI requires the RDF canonicalization test suite, which is embedded as
a git submodule.

```sh
$ git submodule update --init
$ cargo test --workspace
```
