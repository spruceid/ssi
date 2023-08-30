//! The SSI library provides a simple and modular API to sign and verify claims
//! exchanged between applications.
//!
//! It supports the two main families of verifiable claims:
//! - [JSON Web Tokens (JWT)][jwt] where claims are encoded into JSON and
//!   secured using [JSON Web Signatures][jws]; and
//! - [W3C's Verifiable Credentials (VCs)][vc-data-model], a
//!   [Linked-Data][linked-data]-based model where claims (VCs) are interpreted
//!   as RDF datasets. VC supports multiple signature formats provided by SSI:
//!   - VC over JWT ([JWT-VC][jwt-vc]), a restricted form of JWT following the
//!     VC data model; or
//!   - [Data Integrity][data-integrity], encoding the claims and their proof
//!     in the same JSON-LD document.
//!
//! [vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
//! [jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
//! [jws]: <https://www.rfc-editor.org/rfc/rfc7515>
//! [jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
//! [data-integrity]: <https://w3c.github.io/vc-data-integrity/>
//!
//! # Basic Usage
//!
//! This section shows how to create and sign a simple JWT-VC credential.
//! To start of, we need to define our credential schema. In SSI, any Rust type
//! can be used to represent a credential, but to use JWT-VC we will at least
//! need to add serialization/deserialization functions using [`serde`][serde].
//! Don't forget to enable the `derive` feature for `serde`.
//!
//! ```
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct MyCredentialSubject {
//!   name: String,
//!   email: String
//! }
//!
//! let credential = JwtClaims {
//!   subject: MyCredentialSubject {}
//! }
//! ```
//!
//! [serde]: <https://serde.rs/>
//!
//! ```
//! # #[derive(serde::Serialize)]
//! # struct MyCredential { name: String, email: String }
//! use ssi::vc_jwt::JwtVc;
//!
//! // Create the credential.
//! let credential = MyCredential {
//!   name: "John Smith".to_string(),
//!   email: "john.smith@example.org".to_string()
//! };
//!
//! // Create a signer.
//! let signer = SimpleJwkSigner::new(
//!   "http://example.com#key",
//!   jwk
//! );
//!
//! // Sign the credential.
//! let verifiable_credential = JwtVc::sign_json(
//!   signer,
//!   credential
//! ).await;
//! ```
//!
//! # Linked-Data Credentials
//!
//! ```
//! #[derive(LinkedData)]
//! #[ld(prefix("schema", "https://schema.org/"))]
//! struct MyCredentialSubject {
//!   #[ld("schema:name")]
//!   name: String,
//!
//!   #[ld("schema:email")]
//!   email: String
//! }
//!
//! let credential = VerifiableCredential {
//!   subject: MyCredentialSubject {
//!     name: "John Smith".to_string(),
//!     email: "john.smith@example.org".to_string()
//!   }
//!   ..Default::default()
//! }
//! ```
//!
//! ```
//! // Sign the credential, with Linked-Data.
//! let verifiable_credential = JwtVc::sign_ld(
//!   signer,
//!   credential
//! ).await;
//! ```
//!
//! ## Data Integrity
//!
//! ```
//! use ssi::data_integrity::DataIntegrity;
//!
//! // Use a Data Integrity LD Cryptographic Suite.
//! let verifiable_credential = DataIntegrity::sign_ld(
//!   signer,
//!   credential
//! ).await;
//! ```
//!
//! # The `Verifier` trait
//!
//! When verifying a VC, an implementation of the [`Verifier`] trait must be
//! provided. This verifier is in charge of retreiving the
//! ["Verification Method"][verification-methods] referenced in the VC proof and
//! using it to validate the proof.
//!
//! SSI provides the following verifiers:
//!   - [`crate::did::Provider`]: A verifier able to retreive a verification
//!     method from a [Decentralized IDentifier (DID)][did].
//!     See the [`crate::did`] module for more informations about DID support in
//!     SSI.
//!
//! [verifier]: [`crate::verification_methods::Verifier`]
//! [verification-methods]: <https://w3c.github.io/vc-data-integrity/#verification-methods>
//! [did]: <https://www.w3.org/TR/did-core/>
//!
//! # The `Signer` trait
//!
//! When signing a VC, an implementation of the [`Signer`] trait must be
//! provided. The signer is in charge of retreiving the secret signing material
//! associated to a verification method and sign whatever data it is passed.
//!
//! ## Features
//!
//! Feature               | Default | Description
//! ---------------------:|:-------:|-------------
//! `w3c`                 |    ✅   | Enable W3C (i.e. general purpose) related signature suites and cryptographic dependencies.
//! `ed25519`             |    ✅   | Enable EdDSA signature suites and cryptographic dependencies.
//! `rsa`                 |    ✅   | Enable RSA signature suites and cryptographic dependencies.
//! `ripemd-160`          |    ✅   | Enable RIPEMD-160 hashes, useful for Bitcoin addresses.
//! `bbs`                 |         | Enable BBS related signature suites and cryptographic dependencies.
//! `aleo`                |         | Enable Aleo related signature suites and cryptographic dependencies.
//! `eip`                 |    ✅   | Enable Ethereum related signature suites and cryptographic dependencies.
//! `tezos`               |    ✅   | Enable Tezos related signature suites and cryptographic dependencies.
//! `solana`              |         | Enable Solana related signature suites and cryptographic dependencies.
//! `ring`                |         | Use the [ring](https://crates.io/crates/ring) crate for RSA, Ed25519, and SHA-256 functionality.
//! `http-did`            |         | Enable DID resolution tests using [hyper](https://crates.io/crates/hyper) and [tokio](https://crates.io/crates/tokio).
//! `example-http-issuer` |         | Enable resolving example HTTPS Verifiable credential Issuer URL, for [VC Test Suite](https://github.com/w3c/vc-test-suite/).
#![cfg_attr(docsrs, feature(doc_auto_cfg), feature(doc_cfg))]

// // maintain old structure here
// pub use ssi_caips as caips;
// #[deprecated = "Use ssi::caips::caip10"]
// pub use ssi_caips::caip10;
// #[deprecated = "Use ssi::caips::caip2"]
// pub use ssi_caips::caip2;
// pub use ssi_core as core;
// #[deprecated = "Use ssi::core::one_or_many"]
// pub use ssi_core::one_or_many;
// pub use ssi_crypto as crypto;
// #[deprecated = "Use ssi::crypto::hashes"]
// pub use ssi_crypto::hashes as hash;
// #[cfg(feature = "eip")]
// #[deprecated = "Use ssi::crypto::hashes::keccak"]
// pub use ssi_crypto::hashes::keccak;
// #[cfg(feature = "bbs")]
// #[deprecated = "Use ssi::crypto::signatures::bbs"]
// pub use ssi_crypto::signatures::bbs;
// pub use ssi_dids as did;
// #[deprecated = "Use ssi::did::did_resolve"]
// pub use ssi_dids::did_resolve;
// pub use ssi_json_ld as jsonld;
// #[deprecated = "Use ssi::jsonld::rdf"]
// pub use ssi_json_ld::rdf;
// #[deprecated = "Use ssi::jsonld::urdna2015"]
// pub use ssi_json_ld::urdna2015;
// pub use ssi_jwk as jwk;
// #[cfg(feature = "aleo")]
// #[deprecated = "Use ssi::jwk::aleo"]
// pub use ssi_jwk::aleo;
// #[deprecated = "Use ssi::jwk::blakesig"]
// pub use ssi_jwk::blakesig;
// #[deprecated = "Use ssi::jwk::der"]
// pub use ssi_jwk::der;
// #[cfg(feature = "ripemd-160")]
// #[deprecated = "Use ssi::jwk::ripemd160"]
// pub use ssi_jwk::ripemd160 as ripemd;
// pub use ssi_jws as jws;
// pub use ssi_jwt as jwt;
// pub use ssi_ldp as ldp;
// #[cfg(feature = "eip")]
// #[deprecated = "Use ssi::ldp::eip712"]
// pub use ssi_ldp::eip712;
// #[deprecated = "Use ssi::ldp::soltx"]
// pub use ssi_ldp::soltx;
// pub use ssi_ssh as ssh;
// pub use ssi_tzkey as tzkey;
// pub use ssi_ucan as ucan;
pub use ssi_vc as vc;
// #[deprecated = "Use ssi::vc::revocation"]
// pub use ssi_vc::revocation;
// pub use ssi_zcap_ld as zcap;

// pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
