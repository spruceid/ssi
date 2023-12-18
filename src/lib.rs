//! This crate provides core functionality for Verifiable Credentials and Decentralized
//! Identifiers.
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

// maintain old structure here
pub use ssi_caips as caips;
#[deprecated = "Use ssi::caips::caip10"]
pub use ssi_caips::caip10;
#[deprecated = "Use ssi::caips::caip2"]
pub use ssi_caips::caip2;
pub use ssi_core as core;
#[deprecated = "Use ssi::core::one_or_many"]
pub use ssi_core::one_or_many;
pub use ssi_crypto as crypto;
#[deprecated = "Use ssi::crypto::hashes"]
pub use ssi_crypto::hashes as hash;
#[cfg(feature = "eip")]
#[deprecated = "Use ssi::crypto::hashes::keccak"]
pub use ssi_crypto::hashes::keccak;
#[cfg(feature = "bbs")]
#[deprecated = "Use ssi::crypto::signatures::bbs"]
pub use ssi_crypto::signatures::bbs;
pub use ssi_dids as did;
#[deprecated = "Use ssi::did::did_resolve"]
pub use ssi_dids::did_resolve;
pub use ssi_json_ld as jsonld;
#[deprecated = "Use ssi::jsonld::rdf"]
pub use ssi_json_ld::rdf;
#[deprecated = "Use ssi::jsonld::urdna2015"]
pub use ssi_json_ld::urdna2015;
pub use ssi_jwk as jwk;
#[cfg(feature = "aleo")]
#[deprecated = "Use ssi::jwk::aleo"]
pub use ssi_jwk::aleo;
#[deprecated = "Use ssi::jwk::blakesig"]
pub use ssi_jwk::blakesig;
#[deprecated = "Use ssi::jwk::der"]
pub use ssi_jwk::der;
#[cfg(feature = "ripemd-160")]
#[deprecated = "Use ssi::jwk::ripemd160"]
pub use ssi_jwk::ripemd160 as ripemd;
pub use ssi_jws as jws;
pub use ssi_jwt as jwt;
pub use ssi_ldp as ldp;
#[cfg(feature = "eip")]
#[deprecated = "Use ssi::ldp::eip712"]
pub use ssi_ldp::eip712;
#[deprecated = "Use ssi::ldp::soltx"]
pub use ssi_ldp::soltx;
pub use ssi_sd_jwt as sd_jwt;
pub use ssi_ssh as ssh;
pub use ssi_tzkey as tzkey;
pub use ssi_ucan as ucan;
pub use ssi_vc as vc;
#[deprecated = "Use ssi::vc::revocation"]
pub use ssi_vc::revocation;
pub use ssi_zcap_ld as zcap;

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
