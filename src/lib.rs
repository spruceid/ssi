//! The SSI library provides a simple and modular API to sign and verify claims
//! exchanged between applications using
//! [Decentralized Identifiers (DIDs)][dids]. SSI is embedded in the
//! cross-platform [`didkit`][didkit] library as a core dependency.
//!
//! This library supports the two main families of verifiable claims:
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
//!     [*cryptographic suites*][cryptosuite].
//!
//! [dids]: <https://www.w3.org/TR/did-core/>
//! [didkit]: <https://github.com/spruceid/didkit>
//! [vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
//! [linked-data]: <https://www.w3.org/DesignIssues/LinkedData.html>
//! [jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
//! [jws]: <https://www.rfc-editor.org/rfc/rfc7515>
//! [jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
//! [data-integrity]: <https://www.w3.org/TR/vc-data-integrity/>
//! [cryptosuite]: <https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite>
//!
//! # Basic Usage
//!
//! SSI provides various functions to parse, verify, create and sign various
//! kind of claims. This section shows how to use these functions in combination
//! with JSON Web Signatures (or Tokens) and Verifiable Credentials.
//!
//! ## Verification
//!
//! The simplest type of claim to load and verify is probably JSON Web
//! Signatures (JWSs), often use to encode JSON Web Tokens (JWTs). To represent
//! such claims SSI provides the `JwsBuf` type representing a JWS
//! in compact textual form. One can load a JWS using [`new`] and verify
//! it using [`verify`].
//!
//! [`new`]: claims::JwsBuf::new
//! [`verify`]: claims::JwsSlice::verify
//!
//! ```
//! # use ssi_dids::example::ExampleDIDResolver;
//! # #[async_std::main]
//! # async fn main() {
//! use ssi::prelude::*;
//!
//! // Load a JWT from the file system.
//! let jwt = JwsBuf::new(
//!   std::fs::read_to_string("examples/files/claims.jwt")
//!   .expect("unable to load JWT")
//! ).expect("invalid JWS");
//!
//! // Setup a verification method resolver, in charge of retrieving the
//! // public key used to sign the JWT.
//! // Here we use the example `ExampleDIDResolver` resolver, enabled with the
//! // `example` feature.
//! let vm_resolver = ExampleDIDResolver::default().into_vm_resolver::<AnyJwkMethod>();
//!
//! // Setup the verification parameters.
//! let params = VerificationParameters::from_resolver(vm_resolver);
//!
//! // Verify the JWT.
//! assert!(jwt.verify(&params).await.expect("verification failed").is_ok())
//! # }
//! ```
//!
//! ### Verifiable Credentials
//!
//! Verifiable Credential are much more complex as they require interpreting
//! the input claims and proofs, such as Data-Integrity proofs as Linked-Data
//! using JSON-LD. This operation is highly configurable. SSI provide
//! functions exposing various levels of implementation details that you can
//! tweak as needed. The simplest of them is [`any_credential_from_json_str`]
//! that will simply load a VC from a string, assuming it is signed using
//! any Data-Integrity proof supported by SSI.
//!
//! [`any_credential_from_json_str`]: claims::vc::v1::data_integrity::any_credential_from_json_str
//!
//! ```
//! # use ssi_dids::example::ExampleDIDResolver;
//! # #[async_std::main]
//! # async fn main() {
//! use ssi::prelude::*;
//!
//! let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
//!   &std::fs::read_to_string("examples/files/vc.jsonld")
//!   .expect("unable to load VC")
//! ).expect("invalid VC");
//!
//! // Setup a verification method resolver, in charge of retrieving the
//! // public key used to sign the JWT.
//! let vm_resolver = ExampleDIDResolver::default().into_vm_resolver();
//!
//! // Setup the verification parameters.
//! let params = VerificationParameters::from_resolver(vm_resolver);
//!
//! assert!(vc.verify(&params).await.expect("verification failed").is_ok());
//! # }
//! ```
//!
//! ## Signature & Custom Claims
//!
//! In the previous section we have seen how to load and verify arbitrary
//! claims. This section shows how to create and sign custom claims.
//! With SSI, any Rust type can serve as claims as long as it complies to
//! certain conditions such as implementing serialization/deserialization
//! functions using [`serde`](https://crates.io/crates/serde).
//! Don't forget to enable the `derive` feature for `serde`.
//!
//! In the following example, we create a custom type `MyClaims` and sign it
//! as a JWT.
//!
//! ```
//! # #[async_std::main]
//! # async fn main() {
//! use serde::{Serialize, Deserialize};
//! use ssi::prelude::*;
//!
//! // Defines the shape of our custom claims.
//! #[derive(Serialize, Deserialize)]
//! pub struct MyClaims {
//!   name: String,
//!   email: String
//! }
//!
//! // Create JWT claims from our custom ("private") claims.
//! let claims = JWTClaims::from_private_claims(MyClaims {
//!   name: "John Smith".to_owned(),
//!   email: "john.smith@example.org".to_owned()
//! });
//!
//! // Create a random signing key, and turn its public part into a DID URL.
//! let mut key = JWK::generate_p256(); // requires the `p256` feature.
//! let did = DIDJWK::generate_url(&key.to_public());
//! key.key_id = Some(did.into());
//!
//! // Sign the claims.
//! let jwt = claims.sign(&key).await.expect("signature failed");
//!
//! // Create a verification method resolver, which will be in charge of
//! // decoding the DID back into a public key.
//! let vm_resolver = DIDJWK.into_vm_resolver::<AnyJwkMethod>();
//!
//! // Setup the verification parameters.
//! let params = VerificationParameters::from_resolver(vm_resolver);
//!
//! // Verify the JWT.
//! assert!(jwt.verify(&params).await.expect("verification failed").is_ok());
//!
//! // Print the JWT.
//! println!("{jwt}")
//! # }
//! ```
//!
//! ### Verifiable Credential
//!
//! We can use a similar technique to sign a VC with custom claims.
//! The [`SpecializedJsonCredential`] type provides a customizable
//! implementation of the VC data-model 1.1 where you can set the credential type
//! yourself.
//!
//! [`SpecializedJsonCredential`]: claims::vc::v1::SpecializedJsonCredential
//!
//! ```
//! # #[async_std::main]
//! # async fn main() {
//! use static_iref::uri;
//! use serde::{Serialize, Deserialize};
//! use ssi::prelude::*;
//!
//! // Defines the shape of our custom claims.
//! #[derive(Serialize, Deserialize)]
//! pub struct MyCredentialSubject {
//!   #[serde(rename = "https://example.org/#name")]
//!   name: String,
//!
//!   #[serde(rename = "https://example.org/#email")]
//!   email: String
//! }
//!
//! let credential = ssi::claims::vc::v1::JsonCredential::<MyCredentialSubject>::new(
//!   Some(uri!("https://example.org/#CredentialId").to_owned()), // id
//!   uri!("https://example.org/#Issuer").to_owned().into(), // issuer
//!   DateTime::now(), // issuance date
//!   vec![MyCredentialSubject {
//!     name: "John Smith".to_owned(),
//!     email: "john.smith@example.org".to_owned()
//!   }]
//! );
//!
//! // Create a random signing key, and turn its public part into a DID URL.
//! let key = JWK::generate_p256(); // requires the `p256` feature.
//! let did = DIDJWK::generate_url(&key.to_public());
//!
//! // Create a verification method resolver, which will be in charge of
//! // decoding the DID back into a public key.
//! let vm_resolver = DIDJWK.into_vm_resolver();
//!
//! // Create a signer from the secret key.
//! // Here we use the simple `SingleSecretSigner` signer type which always uses
//! // the same provided secret key to sign messages.
//! let signer = SingleSecretSigner::new(key.clone()).into_local();
//!
//! // Turn the DID URL into a verification method reference.
//! let verification_method = did.into_iri().into();
//!
//! // Automatically pick a suitable Data-Integrity signature suite for our key.
//! let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
//!   .expect("could not find appropriate cryptosuite");
//!
//! let vc = cryptosuite.sign(
//!   credential,
//!   &vm_resolver,
//!   &signer,
//!   ProofOptions::from_method(verification_method)
//! ).await.expect("signature failed");
//! # }
//! ```
//!  
//! It is critical that custom claims can be interpreted as Linked-Data. In
//! the above example this is done by specifying a serialization URL for each
//! field of `MyCredentialSubject`. This can also be done by creating a custom
//! JSON-LD context and embed it to `credential` using either
//! [`SpecializedJsonCredential`]'s [`context`] field or leveraging its context type
//! parameter.
//!
//! [`context`]: claims::vc::v1::SpecializedJsonCredential::context
//!
//! # Data-Models
//!
//! The examples above are using the VC data-model 1.1, but you ssi also has support for:
//! - [`VC data-model 2.0`]
//! - [`A wrapper type to accept both`]
//!
//! [`VC data-model 2.0`]: claims::vc::v2
//! [`A wrapper type to accept both`]: claims::vc::syntax::AnySpecializedJsonCredential
//!
//! # Features
#![doc = document_features::document_features!()]
#![cfg_attr(docsrs, feature(doc_auto_cfg), feature(doc_cfg))]

/// XSD types.
#[doc(inline)]
pub use xsd_types as xsd;

/// Collection of common names defined by SSI.
pub mod prelude;

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

/// Claims status.
#[doc(inline)]
pub use ssi_status as status;

/// Default verification parameters type.
///
/// This type can be used as parameters of the
/// [`claims::VerifiableClaims::verify`] function for most claims and signature
/// types. It provides sensible defaults for common parameters:
///   - A DID resolver with support for various DID methods,
///   - A JSON-LD document loader recognizing popular JSON-LD contexts,
///   - the current date and time.
pub type DefaultVerificationParameters = claims::VerificationParameters<
    dids::VerificationMethodDIDResolver<dids::AnyDidMethod, verification_methods::AnyMethod>,
>;

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

/// BBS cryptoscheme.
#[cfg(feature = "bbs")]
#[doc(inline)]
pub use ssi_bbs as bbs;
