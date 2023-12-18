#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! # Decentralized Identifiers (DIDs)
//!
//! As specified by [Decentralized Identifiers (DIDs) v1.0 - Core architecture, data model, and representations][did-core].
//!
//! [did-core]: https://www.w3.org/TR/did-core/

use derive_builder::Builder;
use iref::Iri;
use iref::IriRefBuf;
use ssi_caips::caip10::BlockchainAccountId;
use static_iref::iri;
use std::collections::BTreeMap as Map;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

pub mod did_resolve;
pub mod error;

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

use crate::did_resolve::{
    Content, ContentMetadata, DIDResolver, DereferencingInputMetadata, DereferencingMetadata,
    DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    ERROR_METHOD_NOT_SUPPORTED, TYPE_DID_LD_JSON,
};
pub use crate::error::Error;
use ssi_core::one_or_many::OneOrMany;
use ssi_jwk::JWK;

/// A [verification relationship](https://w3c.github.io/did-core/#dfn-verification-relationship).
///
/// The relationship between a [verification method][VerificationMethod] and a DID
/// Subject (as described by a [DID Document][Document]) is considered analogous to a [proof
/// purpose](crate::vc::ProofPurpose).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
pub enum VerificationRelationship {
    AssertionMethod,
    Authentication,
    KeyAgreement,
    ContractAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

impl Default for VerificationRelationship {
    fn default() -> Self {
        Self::AssertionMethod
    }
}

impl FromStr for VerificationRelationship {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "contractAgreement" => Ok(Self::ContractAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(Error::UnsupportedVerificationRelationship),
        }
    }
}

impl TryFrom<String> for VerificationRelationship {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<VerificationRelationship> for String {
    fn from(purpose: VerificationRelationship) -> String {
        match purpose {
            VerificationRelationship::Authentication => "authentication".to_string(),
            VerificationRelationship::AssertionMethod => "assertionMethod".to_string(),
            VerificationRelationship::KeyAgreement => "keyAgreement".to_string(),
            VerificationRelationship::ContractAgreement => "contractAgreement".to_string(),
            VerificationRelationship::CapabilityInvocation => "capabilityInvocation".to_string(),
            VerificationRelationship::CapabilityDelegation => "capabilityDelegation".to_string(),
        }
    }
}

impl VerificationRelationship {
    pub fn to_iri(&self) -> Iri<'static> {
        match self {
            VerificationRelationship::Authentication => {
                iri!("https://w3id.org/security#authenticationMethod")
            }
            VerificationRelationship::AssertionMethod => {
                iri!("https://w3id.org/security#assertionMethod")
            }
            VerificationRelationship::KeyAgreement => {
                iri!("https://w3id.org/security#keyAgreementMethod")
            }
            VerificationRelationship::ContractAgreement => {
                iri!("https://w3id.org/security#contractAgreementMethod")
            }
            VerificationRelationship::CapabilityInvocation => {
                iri!("https://w3id.org/security#capabilityInvocationMethod")
            }
            VerificationRelationship::CapabilityDelegation => {
                iri!("https://w3id.org/security#capabilityDelegationMethod")
            }
        }
    }
}

use async_trait::async_trait;
use chrono::prelude::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ***********************************************
// * Data Structures for Decentralized Identifiers
// * W3C Working Draft 29 May 2020
// * Accessed July 3, 2019
// * https://w3c.github.io/did-core/
// ***********************************************
// @TODO `id` must be URI

/// URI [required](https://www.w3.org/TR/did-core/#production-0) as the first value of the `@context` property for a DID Document in JSON-LD representation.
pub const DEFAULT_CONTEXT: Iri = iri!("https://www.w3.org/ns/did/v1");

/// Aliases for the [default required DID document context URI][DEFAULT_CONTEXT]. Allowed for compatibility reasons. [DEFAULT_CONTEXT][] should be used instead.
pub const DEFAULT_CONTEXT_NO_WWW: Iri = ssi_json_ld::DID_V1_CONTEXT_NO_WWW;
pub const ALT_DEFAULT_CONTEXT: Iri = ssi_json_ld::W3ID_DID_V1_CONTEXT;

/// DID Core v0.11 context URI. Allowed for legacy
/// reasons. The [v1.0 context URI][DEFAULT_CONTEXT] should be used instead.
pub const V0_11_CONTEXT: Iri = iri!("https://w3id.org/did/v0.11");

// @TODO parsed data structs for DID and DIDURL
#[allow(clippy::upper_case_acronyms)]
type DID = String;

/// A [DID URL](https://w3c.github.io/did-core/#did-url-syntax).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct DIDURL {
    /// [DID](https://www.w3.org/TR/did-core/#did-syntax).
    pub did: String,
    /// [DID path](https://www.w3.org/TR/did-core/#path). `path-abempty` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub path_abempty: String,
    /// [DID query](https://www.w3.org/TR/did-core/#query). `query` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub query: Option<String>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment). `fragment` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub fragment: Option<String>,
}

/// Path component for a [Relative DID URL](https://w3c.github.io/did-core/#relative-did-urls).
///
/// `relative-part` from [RFC 3986 - 4.2 Relative
/// Reference](https://www.rfc-editor.org/rfc/rfc3986#section-4.2), excluding network-path references.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RelativeDIDURLPath {
    /// Absolute-path reference. `path-absolute` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    Absolute(String),
    /// Relative-path reference. `path-noscheme` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    NoScheme(String),
    /// Empty path. `path-empty` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    Empty,
}

/// A [Relative DID URL](https://www.w3.org/TR/did-core/#relative-did-urls).
///
/// A kind of [relative reference (RFC 3986)](https://www.rfc-editor.org/rfc/rfc3986#section-4.2)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct RelativeDIDURL {
    /// Path component of a Relative DID URL.
    pub path: RelativeDIDURLPath,
    /// [DID query](https://www.w3.org/TR/did-core/#query) ([RFC 3986 - 3.4. Query](https://www.rfc-editor.org/rfc/rfc3986#section-3.4))
    pub query: Option<String>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment) ([RFC 3986 - 3.5. Fragment](https://www.rfc-editor.org/rfc/rfc3986#section-3.5))
    pub fragment: Option<String>,
}

/// A [DID URL][DIDURL] without a fragment. Used for [Dereferencing the Primary
/// Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary) in [DID URL Dereferencing][crate::did_resolve::dereference].
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct PrimaryDIDURL {
    /// [DID][DIDURL::did]
    pub did: String,
    /// [DID Path][DIDURL::path_abempty]
    pub path: Option<String>,
    /// [DID query][DIDURL::query]
    pub query: Option<String>,
}

/// A [DID document]
///
/// [DID document]: https://www.w3.org/TR/did-core/#dfn-did-documents
#[derive(Debug, Serialize, Deserialize, Builder, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[builder(
    setter(into, strip_option),
    default,
    build_fn(validate = "Self::validate")
)]
pub struct Document {
    /// [`@context`](https://www.w3.org/TR/did-core/#dfn-context) property of a DID document.
    #[serde(rename = "@context")]
    pub context: Contexts,
    /// [DID Subject id](https://www.w3.org/TR/did-core/#did-subject)
    pub id: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`alsoKnownAs`](https://www.w3.org/TR/did-core/#also-known-as) property of a DID document,
    /// expressing other URIs for the DID subject.
    pub also_known_as: Option<Vec<String>>, // TODO: URI
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`controller`](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document,
    /// expressing [DID controllers(s)](https://www.w3.org/TR/did-core/#did-controller).
    pub controller: Option<OneOrMany<DID>>,
    /// [`verificationMethod`](https://www.w3.org/TR/did-core/#dfn-verificationmethod) property of a
    /// DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    /// [`authentication`](https://www.w3.org/TR/did-core/#dfn-authentication) property of a DID
    /// document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [authentication](https://www.w3.org/TR/did-core/#authentication) purposes (e.g. generating [verifiable
    /// presentations][crate::vc::Presentation]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`assertionMethod`](https://www.w3.org/TR/did-core/#dfn-assertionmethod) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [assertion](https://www.w3.org/TR/did-core/#assertion) purposes (e.g. issuing [verifiable
    /// credentials](crate::vc::Credential)).
    pub assertion_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`keyAgreement`](https://www.w3.org/TR/did-core/#dfn-keyagreement) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [key agreement](https://www.w3.org/TR/did-core/#key-agreement) purposes.
    pub key_agreement: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`capabilityInvocation`](https://www.w3.org/TR/did-core/#dfn-capabilityinvocation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [invoking cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-invocation).
    pub capability_invocation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`capabilityDelegation`](https://www.w3.org/TR/did-core/#dfn-capabilitydelegation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [delegating cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-delegation).
    pub capability_delegation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`publicKey`](https://www.w3.org/TR/did-spec-registries/#publickey) property of a DID
    /// document (deprecated in favor of `verificationMethod`).
    pub public_key: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// `service` property of a DID document, expressing
    /// [services](https://www.w3.org/TR/did-core/#services), generally as endpoints.
    pub service: Option<Vec<Service>>,
    /// [Linked data proof](https://w3c-ccg.github.io/ld-proofs/#linked-data-proof-overview) over a
    /// DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    /// Additional properties of a DID document. Some may be registered in [DID Specification
    /// Registries](https://www.w3.org/TR/did-spec-registries/#did-document-properties).
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context) URI or map, for use in the
/// [`@context`](https://www.w3.org/TR/did-core/#dfn-context) property of a [DID
/// document][Document] in JSON-LD representation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Context {
    /// Context referenced by a URL.
    URI(IriRefBuf),
    /// [Embedded context](https://www.w3.org/TR/json-ld11/#dfn-embedded-context).
    Object(Map<String, Value>),
}

/// [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context) value or array of context
/// values, for use in the [`@context`](https://www.w3.org/TR/did-core/#dfn-context) property of a
/// DID document in JSON-LD representation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    /// A single context value.
    One(Context),
    /// An array of context values.
    Many(Vec<Context>),
}

/// A [Verification method](https://www.w3.org/TR/did-core/#verification-methods) map (object) in a DID
/// document.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethodMap {
    /// [@context](https://www.w3.org/TR/did-core/#dfn-context) property of a verification method map. Used if the verification method map uses
    /// some terms not defined in the containing DID document.
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    /// id property ([DID URL][DIDURL]) of a verification method map.
    pub id: String,
    #[serde(rename = "type")]
    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    pub type_: String,
    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [publicKeyJwk](https://www.w3.org/TR/did-core/#dfn-publickeyjwk) property of a verification
    /// method map, representing a [JSON Web Key][JWK].
    // TODO: make sure this JWK does not have private key material
    pub public_key_jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_pgp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // TODO: make Base58 type like Base64urlUIntString
    /// [publicKeyBase58](https://www.w3.org/TR/did-spec-registries/#publickeybase58) property
    /// (deprecated; [Security Vocab definition](https://w3c-ccg.github.io/security-vocab/#publicKeyBase58)) - encodes public key material in Base58.
    pub public_key_base58: Option<String>,
    // TODO: ensure that not both key parameters are set
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [blockchainAccountId](https://www.w3.org/TR/did-spec-registries/#blockchainaccountid)
    /// property ([Security Vocab definition](https://w3c-ccg.github.io/security-vocab/#blockchainAccountId)), encoding a [CAIP-10 Blockchain account id](crate::caip10::BlockchainAccountId).
    pub blockchain_account_id: Option<String>,
    /// Additional JSON properties.
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// A [Verification method](https://www.w3.org/TR/did-core/#verification-methods) in a DID
/// document, embedded or referenced.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum VerificationMethod {
    /// Verification method URL [including a verification method by reference](https://www.w3.org/TR/did-core/#referring-to-verification-methods).
    DIDURL(DIDURL),
    /// Verification method URL (relative reference), [including a verification method by reference](https://www.w3.org/TR/did-core/#referring-to-verification-methods).
    RelativeDIDURL(RelativeDIDURL),
    /// Embedded verification method.
    Map(VerificationMethodMap),
}

/// Value for a [serviceEndpoint](https://www.w3.org/TR/did-core/#dfn-serviceendpoint) property of
/// a [service](https://www.w3.org/TR/did-core/#services) map in a DID document.
///
/// "The value of the serviceEndpoint property MUST be a string \[URI], a map, or a set composed of one or
/// more strings \[URIs] and/or maps."
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ServiceEndpoint {
    URI(String),
    Map(Value),
}

// <https://w3c.github.io/did-core/#service-properties>
/// A [service](https://www.w3.org/TR/did-core/#services) map (object) in a DID document.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// id property (URI) of a service map.
    pub id: String,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>, // TODO: set
    /// [serviceEndpoint](https://www.w3.org/TR/did-core/#dfn-serviceendpoint) property of a
    /// service map
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<OneOrMany<ServiceEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// A [linked data proof](https://w3c-ccg.github.io/data-integrity-spec/#proofs) ([proof
/// object](https://www.w3.org/TR/vc-data-model/#proofs-signatures)) that may
/// be on a [DID document][Document].
///
/// See also the Verifiable Credential [Proof][crate::vc::Proof] type.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    /// Proof type.
    ///
    /// May be registered in [Linked Data Cryptographic Suite
    /// Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/).
    #[serde(rename = "type")]
    pub type_: String,
    /// Additional properties.
    ///
    /// See [Linked Data Proof Overview](hhttps://w3c-ccg.github.io/data-integrity-spec/#proofs) for more info about expected properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// An object from a [DID document][Document] returned by [DID URL
/// dereferencing][crate::did_resolve::dereference].
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Resource {
    /// Verification method map.
    ///
    /// This results from dereferencing a [verification method DID
    /// URL][VerificationMethod::DIDURL].
    VerificationMethod(VerificationMethodMap),
    /// An arbitrary object (map).
    Object(Map<String, Value>),
}

/// Something that can be used to derive (generate) a DID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source<'a> {
    /// A public key.
    Key(&'a JWK),
    /// A public key and additional pattern.
    KeyAndPattern(&'a JWK, &'a str),
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// [DID Parameters](https://www.w3.org/TR/did-core/#did-parameters).
///
/// As specified in DID Core and/or in [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries/#parameters).
pub struct DIDParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // ASCII
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    /// [`relativeRef`](https://www.w3.org/TR/did-spec-registries/#relativeRef-param) parameter.
    pub relative_ref: Option<String>, // ASCII, percent-encoding
    /// [`versionId`](https://www.w3.org/TR/did-spec-registries/#versionId-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>, // ASCII
    /// [`versionTime`](https://www.w3.org/TR/did-spec-registries/#versionTime-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<DateTime<Utc>>, // ASCII
    /// [`hl`](https://www.w3.org/TR/did-spec-registries/#hl-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>, // ASCII
    /// Additional parameters.
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// DID Create Operation
///
/// <https://identity.foundation/did-registration/#create>
pub struct DIDCreate {
    pub update_key: Option<JWK>,
    pub recovery_key: Option<JWK>,
    pub verification_key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Update Operation
///
/// <https://identity.foundation/did-registration/#update>
pub struct DIDUpdate {
    pub did: String,
    pub update_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub operation: DIDDocumentOperation,
    pub options: Map<String, Value>,
}

/// DID Recover Operation
///
/// <https://www.w3.org/TR/did-core/#did-recovery>
pub struct DIDRecover {
    pub did: String,
    pub recovery_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub new_recovery_key: Option<JWK>,
    pub new_verification_key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Deactivate Operation
///
/// <https://identity.foundation/did-registration/#deactivate>
pub struct DIDDeactivate {
    pub did: String,
    pub key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Document Operation
///
/// This should represent [didDocument][dd] and [didDocumentOperation][ddo] specified by DID
/// Registration.
///
/// [dd]: https://identity.foundation/did-registration/#diddocumentoperation
/// [ddo]: https://identity.foundation/did-registration/#diddocument
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "didDocumentOperation", content = "didDocument")]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum DIDDocumentOperation {
    /// Set the contents of the DID document
    ///
    /// setDidDocument operation defined by DIF DID Registration
    SetDidDocument(Document),

    /// Add properties to the DID document
    ///
    /// addToDidDocument operation defined by DIF DID Registration
    AddToDidDocument(HashMap<String, Value>),

    /// Remove properties from the DID document
    ///
    /// removeFromDidDocument operation defined by DIF Registration
    RemoveFromDidDocument(Vec<String>),

    /// Add or update a verification method in the DID document
    SetVerificationMethod {
        vmm: VerificationMethodMap,
        purposes: Vec<VerificationRelationship>,
    },

    /// Add or update a service map in the DID document
    SetService(Service),

    /// Remove a verification method in the DID document
    RemoveVerificationMethod(DIDURL),

    /// Add or update a service map in the DID document
    RemoveService(DIDURL),
}

/// A transaction for a DID method
#[derive(Debug, Serialize, Deserialize, Builder, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DIDMethodTransaction {
    /// DID method name
    pub did_method: String,

    /// Method-specific transaction data
    #[serde(flatten)]
    pub value: Value,
}

/// An error having to do with a [DIDMethod].
#[derive(Error, Debug)]
pub enum DIDMethodError {
    #[error("Not implemented for DID method: {0}")]
    NotImplemented(&'static str),
    #[error("Option '{option}' not supported for DID operation '{operation}'")]
    OptionNotSupported {
        operation: &'static str,
        option: String,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// An implementation of a [DID method](https://www.w3.org/TR/did-core/#dfn-did-methods).
///
/// Depends on the [DIDResolver][] trait.
/// Also includes functionality to [generate][DIDMethod::generate] DIDs.
///
/// Some DID Methods are registered in the [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries/#did-methods).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDMethod: Sync + Send {
    /// Get the DID method's name.
    ///
    /// `method-name` in [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    fn name(&self) -> &'static str;

    // TODO: allow returning errors
    /// Generate a DID from some source.
    fn generate(&self, _source: &Source) -> Option<String> {
        None
    }

    /// Retrieve a DID from a DID method transaction
    fn did_from_transaction(&self, _tx: DIDMethodTransaction) -> Result<String, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("DID from transaction"))
    }

    /// Submit a DID transaction
    async fn submit_transaction(&self, _tx: DIDMethodTransaction) -> Result<Value, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Transaction submission"))
    }

    /// Create a DID
    fn create(&self, _create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Create operation"))
    }

    /// Update a DID
    fn update(&self, _update: DIDUpdate) -> Result<DIDMethodTransaction, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Update operation"))
    }

    /// Recover a DID
    fn recover(&self, _recover: DIDRecover) -> Result<DIDMethodTransaction, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Recover operation"))
    }

    /// Deactivate a DID
    fn deactivate(
        &self,
        _deactivate: DIDDeactivate,
    ) -> Result<DIDMethodTransaction, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Deactivate operation"))
    }

    /// Upcast the DID method as a DID resolver.
    ///
    /// This is a workaround for [not being able to cast a trait object to a supertrait object](https://github.com/rust-lang/rfcs/issues/2765).
    ///
    /// Implementations should simply return `self`.
    fn to_resolver(&self) -> &dyn DIDResolver;
}

/// A collection of DID methods that can be used as a single [DID resolver][DIDResolver].
#[derive(Default)]
pub struct DIDMethods<'a> {
    /// Collection of DID methods by method id.
    pub methods: HashMap<&'a str, Box<dyn DIDMethod>>,
}

#[allow(clippy::borrowed_box)]
impl<'a> DIDMethods<'a> {
    /// Add a DID method to the set. Returns the previous one set for the given method name, if any.
    pub fn insert(&mut self, method: Box<dyn DIDMethod>) -> Option<Box<dyn DIDMethod>> {
        let name = method.name();
        self.methods.insert(name, method)
    }

    /// Get a DID method from the set.
    pub fn get(&self, method_name: &str) -> Option<&Box<dyn DIDMethod>> {
        self.methods.get(method_name)
    }

    /// Upcast the DID method to a [DID resolver instance][DIDResolver].
    pub fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }

    /// Get DID method to handle a given DID.
    // TODO use DID type
    pub fn get_method(&self, did: &str) -> Result<&Box<dyn DIDMethod>, &'static str> {
        let mut parts = did.split(':');
        if parts.next() != Some("did") {
            return Err(ERROR_INVALID_DID);
        };
        let method_name = match parts.next() {
            Some(method_name) => method_name,
            None => {
                return Err(ERROR_INVALID_DID);
            }
        };
        let method = match self.methods.get(method_name) {
            Some(method) => method,
            None => {
                return Err(ERROR_METHOD_NOT_SUPPORTED);
            }
        };
        Ok(method)
    }

    /// Generate a DID given some input.
    pub fn generate(&self, source: &Source) -> Option<String> {
        let (jwk, pattern) = match source {
            Source::Key(_) => {
                // Need name/pattern to select DID method
                return None;
            }
            Source::KeyAndPattern(jwk, pattern) => (jwk, pattern),
        };
        let mut parts = pattern.splitn(2, ':');
        let method_name = parts.next().unwrap();
        let method = match self.methods.get(method_name) {
            Some(method) => method,
            None => return None,
        };
        if let Some(method_pattern) = parts.next() {
            let source = Source::KeyAndPattern(jwk, method_pattern);
            method.generate(&source)
        } else {
            let source = Source::Key(jwk);
            method.generate(&source)
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> DIDResolver for DIDMethods<'a> {
    /// Resolve a DID using the corresponding DID method, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let method = match self.get_method(did) {
            Ok(method) => method,
            Err(err) => return (ResolutionMetadata::from_error(err), None, None),
        };
        method.to_resolver().resolve(did, input_metadata).await
    }

    /// Resolve a DID to a DID document representation, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        let method = match self.get_method(did) {
            Ok(method) => method,
            Err(err) => return (ResolutionMetadata::from_error(err), Vec::new(), None),
        };
        method
            .to_resolver()
            .resolve_representation(did, input_metadata)
            .await
    }

    /// Dereference a DID URL, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn dereference(
        &self,
        did_url: &PrimaryDIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        let method = match self.get_method(&did_url.did) {
            Ok(method) => method,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(err),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        method
            .to_resolver()
            .dereference(did_url, input_metadata)
            .await
    }
}

impl DIDURL {
    /// Convert a DID URL to a [Relative DID URL][RelativeDIDURL], given a DID as base URI.
    pub fn to_relative(&self, base_did: &str) -> Option<RelativeDIDURL> {
        // TODO: support [Reference Resolution](https://tools.ietf.org/html/rfc3986#section-5) more
        // generally, i.e. where the base is a DID URL (not necessarily a DID), and including [path
        // segment normalization](https://tools.ietf.org/html/rfc3986#section-6.2.2.3)
        if self.did != base_did {
            return None;
        }
        Some(RelativeDIDURL {
            path: match RelativeDIDURLPath::from_str(&self.path_abempty) {
                Ok(path) => path,
                Err(_) => return None,
            },
            query: self.query.as_ref().cloned(),
            fragment: self.fragment.as_ref().cloned(),
        })
    }

    /// Convert to a fragment-less DID URL and return the removed fragment.
    ///
    /// The DID URL can be reconstructed using [PrimaryDIDURL::with_fragment].
    pub fn remove_fragment(self) -> (PrimaryDIDURL, Option<String>) {
        (
            PrimaryDIDURL {
                did: self.did,
                path: if !self.path_abempty.is_empty() {
                    Some(self.path_abempty)
                } else {
                    None
                },
                query: self.query,
            },
            self.fragment,
        )
    }
}

impl RelativeDIDURL {
    /// Convert a DID URL to a absolute DID URL, given a DID as base URI,
    /// according to [DID Core - Relative DID URLs](https://w3c.github.io/did-core/#relative-did-urls).
    pub fn to_absolute(&self, base_did: &str) -> DIDURL {
        // TODO: support [Reference Resolution](https://tools.ietf.org/html/rfc3986#section-5) more
        // generally, e.g. when base is not a DID
        DIDURL {
            did: base_did.to_string(),
            path_abempty: self.path.to_string(),
            query: self.query.as_ref().cloned(),
            fragment: self.fragment.as_ref().cloned(),
        }
    }
}

impl PrimaryDIDURL {
    /// Append a [fragment](https://www.w3.org/TR/did-core/#fragment) to construct a DID URL.
    ///
    /// The opposite of [DIDURL::remove_fragment].
    pub fn with_fragment(self, fragment: String) -> DIDURL {
        DIDURL {
            fragment: Some(fragment),
            ..DIDURL::from(self)
        }
    }
}

impl VerificationMethod {
    /// Return a DID URL for this verification method, given a DID as base URI.
    pub fn get_id(&self, did: &str) -> String {
        match self {
            Self::DIDURL(didurl) => didurl.to_string(),
            Self::RelativeDIDURL(relative_did_url) => relative_did_url.to_absolute(did).to_string(),
            Self::Map(map) => map.get_id(did),
        }
    }
}

impl VerificationMethodMap {
    /// Return a DID URL for this verification method, given a DID as base URI
    pub fn get_id(&self, did: &str) -> String {
        if let Ok(rel_did_url) = RelativeDIDURL::from_str(&self.id) {
            rel_did_url.to_absolute(did).to_string()
        } else {
            self.id.to_string()
        }
    }

    /// Get the verification material as a JWK, from the publicKeyJwk property, or converting from other
    /// public key properties as needed.
    pub fn get_jwk(&self) -> Result<JWK, Error> {
        let pk_hex_value = self
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyHex"));
        let pk_multibase_opt = match self.property_set {
            Some(ref props) => match props.get("publicKeyMultibase") {
                Some(Value::String(string)) => Some(string.clone()),
                Some(Value::Null) => None,
                Some(_) => return Err(Error::ExpectedStringPublicKeyMultibase),
                None => None,
            },
            None => None,
        };
        let pk_bytes = match (
            self.public_key_jwk.as_ref(),
            self.public_key_base58.as_ref(),
            pk_hex_value,
            pk_multibase_opt,
        ) {
            (Some(pk_jwk), None, None, None) => return Ok(pk_jwk.clone()),
            (None, Some(pk_bs58), None, None) => bs58::decode(&pk_bs58).into_vec()?,
            (None, None, Some(pk_hex), None) => {
                let pk_hex = match pk_hex {
                    Value::String(string) => string,
                    _ => return Err(Error::HexString),
                };
                let pk_hex = pk_hex.strip_prefix("0x").unwrap_or(pk_hex);
                hex::decode(pk_hex)?
            }
            (None, None, None, Some(pk_mb)) => multibase::decode(pk_mb)?.1,
            (None, None, None, None) => return Err(Error::MissingKey),
            _ => {
                // https://w3c.github.io/did-core/#verification-material
                // "expressing key material in a verification method using both publicKeyJwk and
                // publicKeyBase58 at the same time is prohibited."
                return Err(Error::MultipleKeyMaterial);
            }
        };
        Ok(ssi_jwk::JWK::from_vm_type(&self.type_, pk_bytes)?)
    }

    /// Verify that a given JWK can be used to satisfy this verification method.
    pub fn match_jwk(&self, jwk: &JWK) -> Result<(), Error> {
        if let Some(ref account_id) = self.blockchain_account_id {
            let account_id = BlockchainAccountId::from_str(account_id)?;
            account_id.verify(jwk)?;
        } else {
            let resolved_jwk = self.get_jwk()?;
            if !resolved_jwk.equals_public(jwk) {
                return Err(Error::KeyMismatch);
            }
        }
        Ok(())
    }
}

/// Parse a DID URL.
impl FromStr for DIDURL {
    type Err = Error;
    fn from_str(didurl: &str) -> Result<Self, Self::Err> {
        let mut parts = didurl.splitn(2, '#');
        let before_fragment = parts.next().unwrap().to_string();
        if before_fragment.is_empty() {
            return Err(Error::DIDURL);
        }
        let fragment = parts.next().map(|x| x.to_owned());
        let primary_did_url = PrimaryDIDURL::try_from(before_fragment)?;
        Ok(Self {
            fragment,
            ..DIDURL::from(primary_did_url)
        })
    }
}

/// Parse a primary DID URL.
impl FromStr for PrimaryDIDURL {
    type Err = Error;
    fn from_str(didurl: &str) -> Result<Self, Self::Err> {
        // Allow non-DID URL for testing lds-ed25519-2020-issuer0
        #[cfg(test)]
        if !didurl.starts_with("did:") {
            return Err(Error::DIDURL);
        }
        if didurl.contains('#') {
            return Err(Error::UnexpectedDIDFragment);
        }
        let mut parts = didurl.splitn(2, '?');
        let before_query = parts.next().unwrap();
        let query = parts.next().map(|x| x.to_owned());
        let (did, path) = match before_query.find('/') {
            Some(i) => {
                let (did, path) = before_query.split_at(i);
                (did.to_string(), Some(path.to_string()))
            }
            None => (before_query.to_string(), None),
        };
        Ok(Self { did, path, query })
    }
}

/// Parse a relative DID URL.
impl FromStr for RelativeDIDURL {
    type Err = Error;
    fn from_str(didurl: &str) -> Result<Self, Self::Err> {
        let mut parts = didurl.splitn(2, '#');
        let before_fragment = parts.next().unwrap().to_string();
        let fragment = parts.next().map(|x| x.to_owned());
        let mut parts = before_fragment.splitn(2, '?');
        let before_query = parts.next().unwrap().to_string();
        let query = parts.next().map(|x| x.to_owned());
        let path = RelativeDIDURLPath::from_str(&before_query)?;
        Ok(Self {
            path,
            query,
            fragment,
        })
    }
}

/// Parse a relative DID URL path.
impl FromStr for RelativeDIDURLPath {
    type Err = Error;
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path.is_empty() {
            return Ok(Self::Empty);
        }
        if path.starts_with('/') {
            // path-absolute = "/" [ segment-nz *( "/" segment ) ]
            // segment-nz    = 1*pchar
            // segment       = *pchar
            if path.len() >= 2 && path.chars().nth(1) == Some('/') {
                // Beginning with "//" would make a scheme-relative URI.
                return Err(Error::DIDURL);
            }
            // TODO: validate segment and pchar
            Ok(Self::Absolute(path.to_string()))
        } else {
            // path-noscheme = segment-nz-nc *( "/" segment )
            // segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
            let first_segment = path.split_once('/').map_or(path, |x| x.0).to_string();
            if first_segment.contains(':') {
                // First path segment containing ":" would make an absolute URI.
                return Err(Error::DIDURL);
            }
            // TODO: validate segment-nz-nc and pchar more
            Ok(Self::NoScheme(path.to_string()))
        }
    }
}

/// Serialize a DID URL.
impl fmt::Display for DIDURL {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.did, self.path_abempty)?;
        if let Some(ref query) = self.query {
            write!(f, "?{query}")?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

/// Serialize a relative DID URL.
impl fmt::Display for RelativeDIDURL {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path.fmt(f)?;
        if let Some(ref query) = self.query {
            write!(f, "?{query}")?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

/// Serialize a relative DID URL path.
impl fmt::Display for RelativeDIDURLPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => Ok(()),
            Self::Absolute(string) => string.fmt(f),
            Self::NoScheme(string) => string.fmt(f),
        }
    }
}

/// Serialize a primary DID URL.
impl fmt::Display for PrimaryDIDURL {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.did)?;
        if let Some(ref path) = self.path {
            write!(f, "{path}")?;
        }
        if let Some(ref query) = self.query {
            write!(f, "?{query}")?;
        }
        Ok(())
    }
}

/// needed for #[serde(try_from = "String")]
impl TryFrom<String> for DIDURL {
    type Error = Error;
    fn try_from(didurl: String) -> Result<Self, Self::Error> {
        DIDURL::from_str(&didurl)
    }
}

/// needed for #[serde(into = "String")]
impl From<DIDURL> for String {
    fn from(didurl: DIDURL) -> String {
        format!("{didurl}")
    }
}

/// Convert a primary DID URL into a DID URL.
impl From<PrimaryDIDURL> for DIDURL {
    fn from(primary: PrimaryDIDURL) -> DIDURL {
        DIDURL {
            did: primary.did,
            path_abempty: primary.path.unwrap_or_default(),
            query: primary.query,
            fragment: None,
        }
    }
}

/// needed for #[serde(into = "String")]
impl From<PrimaryDIDURL> for String {
    fn from(didurl: PrimaryDIDURL) -> String {
        format!("{didurl}")
    }
}

/// needed for #[serde(try_from = "String")]
impl TryFrom<String> for PrimaryDIDURL {
    type Error = Error;
    fn try_from(didurl: String) -> Result<Self, Self::Error> {
        PrimaryDIDURL::from_str(&didurl)
    }
}

/// needed for #[serde(try_from = "String")]
impl TryFrom<String> for RelativeDIDURL {
    type Error = Error;
    fn try_from(relative_did_url: String) -> Result<Self, Self::Error> {
        RelativeDIDURL::from_str(&relative_did_url)
    }
}

/// needed for #[serde(into = "String")]
impl From<RelativeDIDURL> for String {
    fn from(relative_did_url: RelativeDIDURL) -> String {
        relative_did_url.to_string()
    }
}

impl Default for Document {
    /// Create a new DID document with an empty string as the id. The empty string is not valid as
    /// a DID, so this should be changed immediately.
    fn default() -> Self {
        Document::new("")
    }
}

impl Default for RelativeDIDURLPath {
    /// The default relative DID URL path is an [empty path][Self::Empty].
    fn default() -> Self {
        Self::Empty
    }
}

/// Convert one or more context values to a [Contexts][] type.
///
/// Validates that the contexts contain the required [default DID document
/// context][DEFAULT_CONTEXT] (or one of the allowed alternatives).
impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = Error;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(Error::MissingContext),
            Some(Context::URI(uri)) => uri.as_iri_ref(),
            Some(Context::Object(_)) => return Err(Error::InvalidContext),
        };
        if first_uri != DEFAULT_CONTEXT
            && first_uri != V0_11_CONTEXT
            && first_uri != ALT_DEFAULT_CONTEXT
            && first_uri != DEFAULT_CONTEXT_NO_WWW
        {
            return Err(Error::InvalidContext);
        }
        Ok(match context {
            OneOrMany::One(context) => Contexts::One(context),
            OneOrMany::Many(contexts) => Contexts::Many(contexts),
        })
    }
}

impl From<Contexts> for OneOrMany<Context> {
    fn from(contexts: Contexts) -> OneOrMany<Context> {
        match contexts {
            Contexts::One(context) => OneOrMany::One(context),
            Contexts::Many(contexts) => OneOrMany::Many(contexts),
        }
    }
}

impl DocumentBuilder {
    /// Validate that the DID document JSON-LD context contains the required [default context URI][DEFAULT_CONTEXT].
    fn validate(&self) -> Result<(), Error> {
        // validate is called before defaults are assigned.
        // None means default will be used.
        if self.id.is_none() || self.id == Some("".to_string()) {
            return Err(Error::MissingDocumentId);
        }
        if let Some(ref context) = self.context {
            let first_context = match context {
                Contexts::One(context) => context,
                Contexts::Many(contexts) => {
                    if contexts.is_empty() {
                        return Err(Error::MissingContext);
                    } else {
                        &contexts[0]
                    }
                }
            };
            let first_uri = match first_context {
                Context::URI(uri) => uri.as_iri_ref(),
                Context::Object(_) => return Err(Error::InvalidContext),
            };
            if first_uri != DEFAULT_CONTEXT
                && first_uri != V0_11_CONTEXT
                && first_uri != ALT_DEFAULT_CONTEXT
                && first_uri != DEFAULT_CONTEXT_NO_WWW
            {
                return Err(Error::InvalidContext);
            }
        }
        Ok(())
    }
}

// When selecting a object from JSON-LD document, @context should be copied into the sub-document.
pub(crate) fn merge_context(dest_opt: &mut Option<Value>, source: &Contexts) {
    let source = OneOrMany::<Context>::from(source.clone());
    let dest = dest_opt.take().unwrap_or(Value::Null);
    let mut dest_array = match dest {
        Value::Array(array) => array,
        Value::Object(object) => vec![Value::Object(object)],
        _ => Vec::new(),
    };
    for context in source {
        let value = match context {
            Context::URI(uri) => Value::String(uri.into_string()),
            Context::Object(hash_map) => {
                let serde_map = hash_map
                    .into_iter()
                    .collect::<serde_json::Map<String, Value>>();
                Value::Object(serde_map)
            }
        };
        dest_array.push(value);
    }
    if !dest_array.is_empty() {
        let dest = if dest_array.len() == 1 {
            dest_array.remove(0)
        } else {
            Value::Array(dest_array)
        };
        dest_opt.replace(dest);
    }
}

impl Document {
    /// Construct a new DID document with the given id (DID) and [default
    /// `@context`][DEFAULT_CONTEXT].
    pub fn new(id: &str) -> Document {
        Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_owned().into())),
            id: String::from(id),
            also_known_as: None,
            controller: None,
            verification_method: None,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: None,
            proof: None,
            property_set: None,
            public_key: None,
        }
    }

    /// Construct a DID document from JSON.
    pub fn from_json(json: &str) -> Result<Document, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Construct a DID document from JSON bytes.
    pub fn from_json_bytes(json: &[u8]) -> Result<Document, serde_json::Error> {
        serde_json::from_slice(json)
    }

    /// Select an object in the DID document.
    ///
    /// Used in [DID URL dereferencing - Dereferencing the Secondary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary), Step 1.1 "... select the JSON-LD object whose id property matches the input DID URL ..."
    pub fn select_object(&self, id: &DIDURL) -> Result<Resource, Error> {
        let id_string = String::from(id.clone());
        let id_relative_string_opt = id.to_relative(&self.id).map(|rel_url| rel_url.to_string());
        for vm in vec![
            &self.verification_method,
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
            &self.public_key,
        ]
        .iter()
        .flat_map(|array| array.iter().flatten())
        {
            if let VerificationMethod::Map(map) = vm {
                if map.id == id_string || Some(&map.id) == id_relative_string_opt.as_ref() {
                    let mut map = map.clone();
                    merge_context(&mut map.context, &self.context);
                    return Ok(Resource::VerificationMethod(map));
                }
            }
        }
        // TODO: generalize. use json-ld
        Err(Error::ResourceNotFound(id.to_string()))
    }

    /// Select a service endpoint object in the DID document.
    ///
    /// Used in [DID URL Dereferencing - Dereferencing the Primary
    /// Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary), Step
    /// 1.1 "... select the service endpoint whose id property contains a fragment which matches
    /// the value of the service DID parameter of the input DID URL"
    pub fn select_service(&self, fragment: &str) -> Option<&Service> {
        for service in self.service.iter().flatten() {
            if let [service_fragment, _] =
                service.id.rsplitn(2, '#').collect::<Vec<&str>>().as_slice()
            {
                if service_fragment == &fragment {
                    return Some(service);
                }
            }
        }
        None
    }

    /// Get verification method ids from a DID document,
    /// optionally limited to a specific [verification relationship](VerificationRelationship).
    pub fn get_verification_method_ids(
        &self,
        verification_relationship: VerificationRelationship,
    ) -> Result<Vec<String>, String> {
        let did = &self.id;
        let vms = match verification_relationship {
            VerificationRelationship::AssertionMethod => &self.assertion_method,
            VerificationRelationship::Authentication => &self.authentication,
            VerificationRelationship::KeyAgreement => &self.key_agreement,
            VerificationRelationship::CapabilityInvocation => &self.capability_invocation,
            VerificationRelationship::CapabilityDelegation => &self.capability_delegation,
            rel => return Err(format!("Unsupported verification relationship: {rel:?}")),
        };
        let vm_ids = vms.iter().flatten().map(|vm| vm.get_id(did)).collect();
        Ok(vm_ids)
    }

    /// Serialize a DID document with a given
    /// [representation](https://www.w3.org/TR/did-core/#representations) identified by a
    /// content-type string.
    pub fn to_representation(&self, content_type: &str) -> Result<Vec<u8>, Error> {
        match content_type {
            TYPE_DID_LD_JSON => Ok(serde_json::to_vec(self)?),
            _ => Err(Error::RepresentationNotSupported),
        }
    }
}

/// Some example functionality.
#[cfg(feature = "example")]
pub mod example {
    use crate::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
    };
    use crate::{DIDMethod, Document};
    use async_trait::async_trait;

    const DOC_JSON_FOO: &str = include_str!("../tests/did-example-foo.json");
    const DOC_JSON_BBS: &str = include_str!("../tests/did-example-bbs.json");
    const DOC_JSON_BAR: &str = include_str!("../tests/did-example-bar.json");
    const DOC_JSON_12345: &str = include_str!("../tests/did-example-12345.json");
    const DOC_JSON_AABB: &str = include_str!("../tests/lds-eip712-issuer.json");

    // For vc-test-suite
    const DOC_JSON_TEST_ISSUER: &str = include_str!("../tests/did-example-test-issuer.json");
    const DOC_JSON_TEST_HOLDER: &str = include_str!("../tests/did-example-test-holder.json");
    const BBSPLUS_DID: &str = "did:key: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";

    /// An implementation of `did:example`.
    ///
    /// For use with [VC Test Suite](https://github.com/w3c/vc-test-suite/) and in other places.
    pub struct DIDExample;

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDMethod for DIDExample {
        fn name(&self) -> &'static str {
            "example"
        }

        fn to_resolver(&self) -> &dyn DIDResolver {
            self
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for DIDExample {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            let doc_str = match did {
                "did:example:foo" => DOC_JSON_FOO,
                "did:example:bar" => DOC_JSON_BAR,
                "did:example:0xab" => DOC_JSON_TEST_ISSUER,
                "did:example:12345" => DOC_JSON_12345,
                "did:example:ebfeb1f712ebc6f1c276e12ec21" => DOC_JSON_TEST_HOLDER,
                "did:example:aaaabbbb" => DOC_JSON_AABB,
                BBSPLUS_DID => DOC_JSON_BBS,
                _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
            };
            let doc: Document = match serde_json::from_str(doc_str) {
                Ok(doc) => doc,
                Err(err) => {
                    return (ResolutionMetadata::from_error(&err.to_string()), None, None);
                }
            };
            (
                ResolutionMetadata {
                    error: None,
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    property_set: None,
                },
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_url() {
        // https://w3c.github.io/did-core/#example-3-a-did-url-with-a-service-did-parameter
        let didurl_str = "did:foo:21tDAKCERh95uGgKbJNHYp?service=agent";
        let didurl = DIDURL::try_from(didurl_str.to_string()).unwrap();
        assert_eq!(
            didurl,
            DIDURL {
                did: "did:foo:21tDAKCERh95uGgKbJNHYp".to_string(),
                path_abempty: "".to_string(),
                query: Some("service=agent".to_string()),
                fragment: None,
            }
        );
    }

    #[test]
    fn did_url_relative_to_absolute() {
        // https://w3c.github.io/did-core/#relative-did-urls
        let relative_did_url_str = "#key-1";
        let did_url_ref = RelativeDIDURL::from_str(relative_did_url_str).unwrap();
        let did = "did:example:123456789abcdefghi";
        let did_url = did_url_ref.to_absolute(did);
        assert_eq!(did_url.to_string(), "did:example:123456789abcdefghi#key-1");
    }

    #[test]
    fn new_document() {
        let id = "did:test:deadbeefcafe";
        let doc = Document::new(id);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn build_document() {
        let id = "did:test:deadbeefcafe";
        let doc = DocumentBuilder::default()
            .id(id.to_owned())
            .build()
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    #[should_panic(expected = "Missing document ID")]
    fn build_document_no_id() {
        let doc = DocumentBuilder::default().build().unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    #[should_panic(expected = "Invalid context")]
    fn build_document_invalid_context() {
        let id = "did:test:deadbeefcafe";
        let doc = DocumentBuilder::default()
            .context(Contexts::One(Context::URI("example:bad".parse().unwrap())))
            .id(id)
            .build()
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    fn document_from_json() {
        let doc_str = "{\
            \"@context\": \"https://www.w3.org/ns/did/v1\",\
            \"id\": \"did:test:deadbeefcafe\"\
        }";
        let id = "did:test:deadbeefcafe";
        let doc = Document::from_json(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn verification_method() {
        let id = "did:test:deadbeefcafe";
        let mut doc = Document::new(id);
        doc.verification_method = Some(vec![VerificationMethod::DIDURL(
            DIDURL::try_from("did:pubkey:okay".to_string()).unwrap(),
        )]);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let pko = VerificationMethodMap {
            id: String::from("did:example:123456789abcdefghi#keys-1"),
            type_: String::from("Ed25519VerificationKey2018"),
            controller: String::from("did:example:123456789abcdefghi"),
            ..Default::default()
        };
        doc.verification_method = Some(vec![
            VerificationMethod::DIDURL(DIDURL::try_from("did:pubkey:okay".to_string()).unwrap()),
            VerificationMethod::Map(pko),
        ]);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn vmm_to_jwk() {
        // Identity: publicKeyJWK -> JWK
        const JWK: &str = include_str!("../../tests/ed25519-2020-10-18.json");
        let jwk: JWK = serde_json::from_str(JWK).unwrap();
        let pk_jwk = jwk.to_public();
        let vmm_ed = VerificationMethodMap {
            id: String::from("did:example:foo#key2"),
            type_: String::from("Ed25519VerificationKey2018"),
            controller: String::from("did:example:foo"),
            public_key_jwk: Some(pk_jwk.clone()),
            ..Default::default()
        };
        let jwk = vmm_ed.get_jwk().unwrap();
        assert_eq!(jwk, pk_jwk);
    }

    #[test]
    fn vmm_bs58_to_jwk() {
        // publicKeyBase58 (deprecated) -> JWK
        const JWK: &str = include_str!("../../tests/ed25519-2020-10-18.json");
        let jwk: JWK = serde_json::from_str(JWK).unwrap();
        let pk_jwk = jwk.to_public();
        let vmm_ed = VerificationMethodMap {
            id: String::from("did:example:foo#key3"),
            type_: String::from("Ed25519VerificationKey2018"),
            controller: String::from("did:example:foo"),
            public_key_base58: Some("2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH".to_string()),
            ..Default::default()
        };
        let jwk = vmm_ed.get_jwk().unwrap();
        assert_eq!(jwk, pk_jwk);
    }

    #[test]
    fn vmm_hex_to_jwk() {
        // publicKeyHex (deprecated) -> JWK
        const JWK: &str = include_str!("../../tests/secp256k1-2021-02-17.json");
        let jwk: JWK = serde_json::from_str(JWK).unwrap();
        let pk_jwk = jwk.to_public();
        let vmm_ed = VerificationMethodMap {
            id: String::from("did:example:deprecated#lds-ecdsa-secp256k1-2019-pkhex"),
            type_: String::from("EcdsaSecp256k1VerificationKey2019"),
            controller: String::from("did:example:deprecated"),
            public_key_jwk: Some(pk_jwk.clone()),
            ..Default::default()
        };
        let jwk = vmm_ed.get_jwk().unwrap();
        assert_eq!(jwk, pk_jwk);
    }
}
