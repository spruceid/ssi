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

pub use xsd_types;

// Re-export core functions and types.
pub use ssi_core::*;

/// Cryptography.
pub use ssi_crypto as crypto;

/// JSON Web Key (JWK).
///
/// See: <https://www.rfc-editor.org/rfc/rfc7517>
pub use ssi_jwk as jwk;

/// RDF utilities.
pub use ssi_rdf as rdf;

/// JSON-LD utilities.
pub use ssi_json_ld as json_ld;

/// W3C's Security Vocabulary.
pub use ssi_security as security;

/// Verifiable Claims.
///
/// Includes Verifiable Credentials and Data-Integrity Proofs.
pub use ssi_claims as claims;

/// Verification Methods.
pub use ssi_verification_methods as verification_methods;

/// Chain Agnostic Improvement Proposals (CAIPs).
///
/// See: <https://chainagnostic.org/>
pub use ssi_caips as caips;

/// Decentralized Identifiers (DIDs).
///
/// See: <https://www.w3.org/TR/did-core/>
pub use ssi_dids as dids;

/// Ethereum Typed Structured Data Hashing and Signing (EIP-712).
///
/// See: <https://eips.ethereum.org/EIPS/eip-712>
pub use ssi_eip712 as eip712;

/// User Controlled Authorization Network (UCAN).
///
/// See: <https://github.com/ucan-wg/spec>
pub use ssi_ucan as ucan;

/// Authorization Capabilities for Linked Data (ZCAP-LD).
///
/// See: <https://w3c-ccg.github.io/zcap-spec/>
pub use ssi_zcap_ld as zcap_ld;

/// Multicodec.
///
/// See: <https://github.com/multiformats/multicodec>
pub use ssi_multicodec as multicodec;

/// Secure Shell utilities.
pub use ssi_ssh as ssh;
