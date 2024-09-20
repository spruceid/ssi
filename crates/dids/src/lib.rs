//! DID Methods.
//!
//! This library provides Decentralized Identifiers (DIDs), a type of
//! identifier defined by the W3C that enables verifiable, self-sovereign
//! digital identities.
//! Unlike traditional identifiers, such as email addresses or usernames,
//! DIDs are not tied to a central authority. Instead, they are generated and
//! managed on decentralized networks like blockchains, providing greater
//! privacy, security, and control to the individual or entity that owns them.
//!
//! Each DID is an URI using the `did` scheme. This library uses the [`DID`] and
//! [`DIDBuf`] (similar to [`str`] and [`String`]) to parse and store DIDs.
//!
//! ```
//! use ssi_dids::{DID, DIDBuf};
//!
//! // Create a `&DID` from a `&str`.
//! let did = DID::new("did:web:w3c-ccg.github.io:user:alice").unwrap();
//!
//! // Create a `DIDBuf` from a `String`.
//! let owned_did = DIDBuf::from_string("did:web:w3c-ccg.github.io:user:alice".to_owned()).unwrap();
//! ```
//!
//! Just like regular URLs, it is possible to provide the DID with a fragment
//! part. The result is a DID URL, which can be parsed and stored using
//! [`DIDURL`] and [`DIDURLBuf`].
//!
//! ```
//! use ssi_dids::{DIDURL, DIDURLBuf};
//!
//! // Create a `&DIDURL` from a `&str`.
//! let did_url = DIDURL::new("did:web:w3c-ccg.github.io:user:alice#key").unwrap();
//!
//! // Create a `DIDBuf` from a `String`.
//! let owned_did_url = DIDURLBuf::from_string("did:web:w3c-ccg.github.io:user:bob#key".to_owned()).unwrap();
//! ```
//!
//! Note that a DID URL, with a fragment, is not a valid DID.
//!
//! # DID document resolution
//!
//! DID resolution is the process of retrieving the DID document associated with
//! a specific DID.
//! A DID document is a JSON-LD formatted file that contains crucial information
//! needed to interact with the DID, such as verification methods containing the
//! user's public keys, and service endpoints. Here is an example DID document:
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/did/v1",
//!     "https://w3id.org/security/suites/jws-2020/v1"
//!   ],
//!   "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
//!   "verificationMethod": [
//!     {
//!       "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0",
//!       "type": "JsonWebKey2020",
//!       "controller": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
//!       "publicKeyJwk": {
//!         "crv": "P-256",
//!         "kty": "EC",
//!         "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
//!         "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
//!       }
//!     }
//!   ],
//!   "assertionMethod": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
//!   "authentication": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
//!   "capabilityInvocation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
//!   "capabilityDelegation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
//!   "keyAgreement": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"]
//! }
//! ```
//!
//! DID documents are represented using the [`Document`] type and can be
//! resolved from a DID using any implementation of the [`DIDResolver`] trait.
//! The [`AnyDidMethod`] type is provided as a default implementation for
//! [`DIDResolver`] that supports various *DID methods* (see below).
//!
//! ```
//! # #[async_std::main] async fn main() {
//! use ssi_dids::{DID, AnyDidMethod, DIDResolver};
//!
//! // Create a DID.
//! let did = DID::new("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9").unwrap();
//!
//! // Setup the DID resolver.
//! let resolver = AnyDidMethod::default();
//!
//! // Resolve the DID document (equal to the example document above).
//! let document = resolver.resolve(did).await.unwrap().document;
//!
//! // Extract the first verification method.
//! let vm = document.verification_method.first().unwrap();
//! # }
//! ```
//!
//! Instead of resolving a DID document and extracting verification methods
//! manually, you can use the `dereference` method to resolve a DID URL:
//! ```
//! # #[async_std::main] async fn main() {
//! use ssi_dids::{DIDURL, AnyDidMethod, DIDResolver};
//!
//! // Create a DID URL with the fragment `#0` referencing a verification method.
//! let did_url = DIDURL::new("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0").unwrap();
//!
//! // Setup the DID resolver.
//! let resolver = AnyDidMethod::default();
//!
//! // Dereference the verification method.
//! let vm = resolver
//!   .dereference(did_url)
//!   .await
//!   .unwrap()
//!   .content
//!   .into_verification_method()
//!   .unwrap();
//! # }
//! ```
//!
//! # DID methods
//!
//! A key component of the DID system is the concept of DID methods. A DID
//! method defines how a specific type of DID is created, resolved, updated,
//! and deactivated on a particular decentralized network or ledger.
//! Each DID method corresponds to a unique identifier format and a set of
//! operations that can be performed on the associated DIDs.
//! The general syntax of DIDs depends on the method used:
//!
//! ```text
//! did:method:method-specific-id
//! ```
//!
//! There exists various DID methods, each defined by their own specification.
//! In this library, methods are defining by implementing the [`DIDMethod`]
//! trait. Implementations are provided for the following methods:
//! - [`did:key`](https://w3c-ccg.github.io/did-method-key/): for static
//!   cryptographic keys, implemented by [`DIDKey`].
//! - [`did:jwk`](https://github.com/quartzjer/did-jwk/blob/main/spec.md):
//!   for [Json Web Keys (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
//!   implemented by [`DIDJWK`].
//! - [`did:web`](https://w3c-ccg.github.io/did-method-web/): for web-hosted DID
//!   documents, implemented by [`DIDWeb`].
//! - [`did:pkh`](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md):
//!   implemented by [`DIDPKH`].
//! - [`did:ethr`](https://github.com/decentralized-identity/ethr-did-resolver/):
//!   implemented by [`DIDEthr`].
//! - [`did:ion`](https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition):
//!   implemented by [`DIDION`].
//! - [`did:tz`](https://github.com/spruceid/did-tezos/): implemented by
//!   [`DIDTz`].
//!
//! The [`AnyDidMethod`] regroups all those methods into one [`DIDResolver`]
//! implementation.
//!
//! DID method types can also be used to generate fresh DID URLs:
//! ```
//! use ssi_jwk::JWK;
//! use ssi_dids::DIDJWK;
//!
//! /// Generate a new JWK.
//! let jwk = JWK::generate_p256();
//!
//! /// Generate a DID URL out of our JWK URL.
//! let did_url = DIDJWK::generate_url(&jwk);
//! ```

// Re-export core definitions.
pub use ssi_dids_core::*;

// Re-export DID methods implementations.
pub use did_ethr as ethr;
pub use did_ion as ion;
pub use did_jwk as jwk;
pub use did_method_key as key;
pub use did_pkh as pkh;
pub use did_tz as tz;
pub use did_web as web;

pub use ethr::DIDEthr;
pub use ion::DIDION;
pub use jwk::DIDJWK;
pub use key::DIDKey;
pub use pkh::DIDPKH;
pub use tz::DIDTz;
pub use web::DIDWeb;

/// DID generation error.
///
/// Error raised by the [`AnyDidMethod::generate`] method.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error(transparent)]
    Ethr(ssi_jwk::Error),

    #[error(transparent)]
    Key(key::GenerateError),

    #[error(transparent)]
    Pkh(pkh::GenerateError),

    #[error(transparent)]
    Tz(ssi_jwk::Error),

    #[error("unsupported method pattern `{0}`")]
    UnsupportedMethodPattern(String),
}

/// DID resolver for any known DID method.
///
/// This type regroups all the [`DIDMethod`] implementations provided by `ssi`
/// into a single [`DIDResolver`] trait implementation.
///
/// # Supported methods
///
/// Here is the list of DID methods currently supported by this resolver:
/// - [`did:key`](https://w3c-ccg.github.io/did-method-key/): for static
///   cryptographic keys, implemented by [`DIDKey`].
/// - [`did:jwk`](https://github.com/quartzjer/did-jwk/blob/main/spec.md):
///   for [Json Web Keys (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
///   implemented by [`DIDJWK`].
/// - [`did:web`](https://w3c-ccg.github.io/did-method-web/): for web-hosted DID
///   documents, implemented by [`DIDWeb`].
/// - [`did:pkh`](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md):
///   implemented by [`DIDPKH`].
/// - [`did:ethr`](https://github.com/decentralized-identity/ethr-did-resolver/):
///   implemented by [`DIDEthr`].
/// - [`did:ion`](https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition):
///   implemented by [`DIDION`].
/// - [`did:tz`](https://github.com/spruceid/did-tezos/): implemented by
///   [`DIDTz`].
#[derive(Default, Clone)]
pub struct AnyDidMethod {
    /// `did:ion` method configuration.
    ion: DIDION,

    /// `did:tz` method configuration.
    tz: DIDTz,
}

impl AnyDidMethod {
    /// Creates a new resolver using the following `did:ion` and `did:tz` method
    /// resolvers.
    ///
    /// Use the [`Default`] implementation if you don't want to configure
    /// `DIDION` and `DIDTz` yourself.
    pub fn new(ion: DIDION, tz: DIDTz) -> Self {
        Self { ion, tz }
    }

    /// Generate a new DID from a JWK.
    ///
    /// The `method_pattern` argument is used to select and configure the DID
    /// method. Accepted patterns are
    /// - `key` to generate a `did:key` DID,
    /// - `jwk` to generate a `did:jwk` DID,
    /// - `ethr` to generate a `did:ethr` DID,
    /// - `pkh:{pkh_name}` to generate a `did:pkh` DID, where `{pkh_name}`
    ///    should be replaced by the network id as specified by the
    ///    [`DIDPKH::generate`] function.
    /// - `tz` to generate a `did:tz` DID.
    ///
    /// # Example
    ///
    /// ```
    /// use ssi_jwk::JWK;
    /// use ssi_dids::AnyDidMethod;
    ///
    /// // Create a DID resolver.
    /// let resolver = AnyDidMethod::default();
    ///
    /// // Create a JWK.
    /// let jwk = JWK::generate_p256();
    ///
    /// // Generate a `did:jwk` DID for this JWK:
    /// let did = resolver.generate(&jwk, "jwk").unwrap();
    /// ```
    pub fn generate(
        &self,
        key: &ssi_jwk::JWK,
        method_pattern: &str,
    ) -> Result<DIDBuf, GenerateError> {
        match method_pattern
            .split_once(':')
            .map(|(m, p)| (m, Some(p)))
            .unwrap_or((method_pattern, None))
        {
            ("ethr", None) => ethr::DIDEthr::generate(key).map_err(GenerateError::Ethr),
            ("jwk", None) => Ok(jwk::DIDJWK::generate(key)),
            ("key", None) => key::DIDKey::generate(key).map_err(GenerateError::Key),
            ("pkh", Some(pkh_name)) => {
                pkh::DIDPKH::generate(key, pkh_name).map_err(GenerateError::Pkh)
            }
            ("tz", None) => self.tz.generate(key).map_err(GenerateError::Tz),
            _ => Err(GenerateError::UnsupportedMethodPattern(
                method_pattern.to_string(),
            )),
        }
    }
}

impl DIDResolver for AnyDidMethod {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            "ethr" => {
                ethr::DIDEthr
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "ion" => {
                self.ion
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "jwk" => {
                DIDJWK
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "key" => {
                DIDKey
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "pkh" => {
                DIDPKH
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "tz" => {
                self.tz
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "web" => {
                DIDWeb
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            m => Err(resolution::Error::MethodNotSupported(m.to_owned())),
        }
    }
}
