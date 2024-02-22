//! The SSI library provides a simple and modular API to sign and verify claims
//! exchanged between applications using
//! [Decentralized Identifiers (DIDs)][dids].
//!
//! It supports the two main families of verifiable claims:
//! - [JSON Web Tokens (JWT)][jwt] where claims are encoded into JSON and
//!   secured using [JSON Web Signatures][jws]; and
//! - [W3C's Verifiable Credentials (VCs)][vc-data-model], a
//!   [Linked-Data][linked-data]-based model where claims (VCs) can be
//!   interpreted as RDF datasets. VC supports multiple signature formats
//!   provided by SSI:
//!   - VC over JWT ([JWT-VC][jwt-vc]), a restricted form of JWT following the
//!     VC data model; or
//!   - [Data Integrity][data-integrity], encoding the claims and their proof
//!     in the same JSON-LD document using a wide variety of
//!     [*cryptographic suites*](cryptosuite).
//!
//! [dids]: <https://www.w3.org/TR/did-core/>
//! [vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
//! [jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
//! [jws]: <https://www.rfc-editor.org/rfc/rfc7515>
//! [jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
//! [data-integrity]: <https://www.w3.org/TR/vc-data-integrity/>
//! [cryptosuite]: <https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite>
//!
//! # Basic Usage
//!
//! This section shows how to create and sign a simple JWT with custom claims.
//! In SSI, any Rust type can serve as claims, but to build the final JWT we
//! will at least need to add serialization/deserialization functions using
//! [`serde`][serde]. Don't forget to enable the `derive` feature for `serde`.
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use ssi::{JWK, claims::JWTClaims, dids::{DIDResolver, DIDJWK}};
//!
//! // Defines the shape of our custom claims.
//! #[derive(Serialize, Deserialize)]
//! pub struct MyClaims {
//!   name: String,
//!   email: String
//! }
//!
//! // Create JWT claims from our custom ("private") claims.
//! let claims = JwtClaims::from_private_claims(MyClaims {
//!   name: "John Smith".to_owned(),
//!   email: "john.smith@example.org".to_owned()
//! });
//!
//! // Create a random signing key, and turn its public part into a DID.
//! let key = JWK::generate_p256(); // requires the `p256` feature.
//! let did = DIDJWK::generate(key.to_public_key());
//!
//! // Create a verification method resolver, which will be in charge of
//! // decoding the DID back into a public key.
//! let vm_resolver = DIDJWK.with_default_options();
//!
//! // Create a signer from the secret key.
//! // Here we use the simple `SingleSecretSigner` signer type which always uses
//! // the same provided secret key to sign messages.
//! let signer = SingleSecretSigner::new(key);
//!
//! // Sign the claims.
//! let jwt = claims.sign(
//!   &did,
//!   &vm_resolver,
//!   &signer
//! ).await.expect("signature failed");
//!
//! // Verify the JWT.
//! assert!(jwt.verify(&vm_resolver).await.expect("verification failed").is_valid())
//!
//! // Print the JWT.
//! println!("{jwt}")
//! ```
//!
//! # The `Signer` trait
//!
//! When signing a VC, an implementation of the [`Signer`] trait must be
//! provided. The signer is in charge of retreiving the secret signing material
//! associated to a verification method and sign whatever data it is passed.
//!
//! # Features
#![doc = document_features::document_features!()]
#![cfg_attr(docsrs, feature(doc_auto_cfg), feature(doc_cfg))]

pub use xsd_types;

// Re-export core functions and types.
#[doc(hidden)]
pub use ssi_core::*;

/// Cryptography.
#[doc(inline)]
pub use ssi_crypto as crypto;

/// JSON Web Key (JWK).
///
/// See: <https://www.rfc-editor.org/rfc/rfc7517>
#[doc(inline)]
pub use ssi_jwk as jwk;

/// JSON Web Key (JWK).
#[doc(inline)]
pub use jwk::JWK;

/// RDF utilities.
#[doc(inline)]
pub use ssi_rdf as rdf;

/// JSON-LD utilities.
#[doc(inline)]
pub use ssi_json_ld as json_ld;

/// W3C's Security Vocabulary.
#[doc(inline)]
pub use ssi_security as security;

/// Verifiable Claims.
///
/// Includes Verifiable Credentials and Data-Integrity Proofs.
#[doc(inline)]
pub use ssi_claims as claims;

/// Verification Methods.
#[doc(inline)]
pub use ssi_verification_methods as verification_methods;

/// Chain Agnostic Improvement Proposals (CAIPs).
///
/// See: <https://chainagnostic.org/>
#[doc(inline)]
pub use ssi_caips as caips;

/// Decentralized Identifiers (DIDs).
///
/// See: <https://www.w3.org/TR/did-core/>
#[doc(inline)]
pub use ssi_dids as dids;

/// Ethereum Typed Structured Data Hashing and Signing (EIP-712).
///
/// See: <https://eips.ethereum.org/EIPS/eip-712>
#[doc(inline)]
pub use ssi_eip712 as eip712;

/// User Controlled Authorization Network (UCAN).
///
/// See: <https://github.com/ucan-wg/spec>
#[doc(inline)]
pub use ssi_ucan as ucan;

/// Authorization Capabilities for Linked Data (ZCAP-LD).
///
/// See: <https://w3c-ccg.github.io/zcap-spec/>
#[doc(inline)]
pub use ssi_zcap_ld as zcap_ld;

/// Multicodec.
///
/// See: <https://github.com/multiformats/multicodec>
#[doc(inline)]
pub use ssi_multicodec as multicodec;

/// Secure Shell utilities.
#[doc(inline)]
pub use ssi_ssh as ssh;
