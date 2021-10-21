//! This crate provides core functionality for Verifiable Credentials and Decentralized
//! Identifiers.
//!
//! ## Features
//!
//! Default: `ring`
//!
//! Feature               | Description
//! ----------------------|-------------
//! `ring`                | Use the [ring](https://crates.io/crates/ring) crate for RSA, Ed25519, and SHA-256 functionality. Conflicts with `rsa`, `ed25519-dalek`, and `sha` features.
//! `rsa`                 | Use the [rsa](https://crates.io/crates/rsa) crate for RSA functionality. Conflicts with `ring` feature.
//! `http-did`            | Enable DID resolution tests using [hyper](https://crates.io/crates/hyper) and [tokio](https://crates.io/crates/tokio).
//! `secp256k1`           | Enable Secp256k1 using the [k256](https://crates.io/crates/k256) crate.
//! `secp256r1`           | Enable Secp256r1 using the [p256](https://crates.io/crates/p256) crate.
//! `ripemd-160`          | Enable RIPEMD-160, for Bitcoin addresses, using the [ripemd160](https://crates.io/crates/ripemd160) crate.
//! `keccak`              | Enable Keccak hash, for Ethereum addresses, using the [keccak-hash](https://crates.io/crates/keccak-hash) crate.
//! `sha`                 | Enable SHA-256 using the [sha2](https://crates.io/crates/sha2) crate. Conflicts with `ring` feature.
//! `ed25519-dalek`       | Enable Ed25519 using the [ed25519-dalek](https://crates.io/crates/ed25519-dalek) crate. Conflicts with `ring` feature.
//! `example-http-issuer` | Enable resolving example HTTPS Verifiable credential Issuer URL, for [VC Test Suite](https://github.com/w3c/vc-test-suite/).
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc(
    html_logo_url = "https://demo.didkit.dev/2021/10/21/rust-didkit.png",
    html_favicon_url = "https://demo.didkit.dev/2021/10/21/rust-favicon.ico"
)]
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
pub mod urdna2015;
pub mod vc;
pub mod zcap;

pub static USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(any(feature = "k256", feature = "p256"))]
pub mod passthrough_digest;

extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate json;

#[derive(Parser)]
#[grammar = "did.pest"]
pub struct DidParser;

#[cfg(test)]
mod tests {
    use super::*;

    // use pest::error::Error;
    use pest::Parser;

    #[test]
    fn parse_did_components() {
        let input = "did:deadbeef:cafe/sub/path/?p1=v1&p2=v2#frag1";
        let rv = DidParser::parse(Rule::did_url, input);
        match rv {
            Ok(pairs) => {
                //println!("{:#?}", pairs);
                assert_eq!(input, pairs.as_str()); // ensure complete parsing
                let mut pairs_iter = pairs;
                let mut did_url_pairs_iter = pairs_iter.next().unwrap().into_inner();

                // @TODO: check scheme subtokens (method_name, method_specific_id)
                let did_scheme_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::did_scheme, did_scheme_pair.as_rule());
                assert_eq!("did:deadbeef:cafe", did_scheme_pair.as_str());

                // @TODO: check path_abempty subtokens (segment*)
                let path_abempty_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::path_abempty, path_abempty_pair.as_rule());
                assert_eq!("/sub/path/", path_abempty_pair.as_str());

                let query_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::query, query_pair.as_rule());
                assert_eq!("p1=v1&p2=v2", query_pair.as_str());

                let fragment_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::fragment, fragment_pair.as_rule());
                assert_eq!("frag1", fragment_pair.as_str());
            }
            Err(e) => panic!("error: {}", e),
        }
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
