//! This crate provides core functionality for Verifiable Credentials and Decentralized
//! Identifiers.
//!
//! ## Features
//!
//! Default: `ring`
//!
//! Feature               | Description
//! ----------------------|-------------
//! `ring`                | Use the [ring](https://crates.io/crates/ring) crate for RSA, Ed25519, and SHA-256 functionality. **Conflicts with `rsa`, `ed25519-dalek`, and `sha` features.**
//! `rsa`                 | Use the [rsa](https://crates.io/crates/rsa) crate for RSA functionality. **Conflicts with `ring` feature.**
//! `http-did`            | Enable DID resolution tests using [hyper](https://crates.io/crates/hyper) and [tokio](https://crates.io/crates/tokio).
//! `secp256k1`           | Enable Secp256k1 using the [k256](https://crates.io/crates/k256) crate.
//! `secp256r1`           | Enable Secp256r1 using the [p256](https://crates.io/crates/p256) crate.
//! `ripemd-160`          | Enable RIPEMD-160, for Bitcoin addresses, using the [ripemd160](https://crates.io/crates/ripemd160) crate.
//! `keccak`              | Enable Keccak hash, for Ethereum addresses, using the [keccak-hash](https://crates.io/crates/keccak-hash) crate.
//! `sha`                 | Enable SHA-256 using the [sha2](https://crates.io/crates/sha2) crate. **Conflicts with `ring` feature.**
//! `ed25519-dalek`       | Enable Ed25519 using the [ed25519-dalek](https://crates.io/crates/ed25519-dalek) crate. **Conflicts with `ring` feature.**
//! `example-http-issuer` | Enable resolving example HTTPS Verifiable credential Issuer URL, for [VC Test Suite](https://github.com/w3c/vc-test-suite/).
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc(
    html_logo_url = "https://demo.didkit.dev/2021/10/21/rust-didkit.png",
    html_favicon_url = "https://demo.didkit.dev/2021/10/21/rust-favicon.ico"
)]

#[cfg(feature = "aleosig")]
pub mod aleo;

#[cfg(feature = "bbs")]
pub mod bbs;
pub mod blakesig;
pub mod caip10;
pub mod caip2;
pub mod der;
pub mod did;
pub mod did_resolve;
#[cfg(feature = "keccak-hash")]
pub mod eip712;
pub mod error;
pub mod hash;
pub mod jsonld;
pub mod jwk;
pub mod jws;
pub mod jwt;
#[cfg(feature = "keccak-hash")]
pub mod keccak_hash;
pub mod ldp;
pub mod one_or_many;
pub mod rdf;
pub mod revocation;
#[cfg(feature = "ripemd160")]
pub mod ripemd;
pub mod soltx;
pub mod ssh;
pub mod tzkey;
pub mod ucan;
pub mod urdna2015;
pub mod vc;
pub mod zcap;

pub static USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(any(feature = "k256", feature = "p256"))]
pub mod passthrough_digest;

#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate json;
