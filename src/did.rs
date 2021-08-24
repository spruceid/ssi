use std::collections::BTreeMap as Map;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use crate::did_resolve::{
    Content, ContentMetadata, DIDResolver, DereferencingInputMetadata, DereferencingMetadata,
    DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    ERROR_METHOD_NOT_SUPPORTED, TYPE_DID_LD_JSON,
};
use crate::error::Error;
use crate::jwk::JWK;
use crate::one_or_many::OneOrMany;

/// <https://w3c.github.io/did-core/#dfn-verification-relationship>
type VerificationRelationship = crate::vc::ProofPurpose;

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

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const ALT_DEFAULT_CONTEXT: &str = crate::jsonld::W3ID_DID_V1_CONTEXT;

// v0.11 context used by universal resolver
pub const V0_11_CONTEXT: &str = "https://w3id.org/did/v0.11";

// @TODO parsed data structs for DID and DIDURL
type DID = String;

/// [DID URL](https://w3c.github.io/did-core/#did-url-syntax)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct DIDURL {
    pub did: String,
    pub path_abempty: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

/// Path component for a [Relative DID URL](https://w3c.github.io/did-core/#relative-did-urls).
/// Based on [RFC 3886 - Path syntax](https://tools.ietf.org/html/rfc3986#section-3.3) and
/// [Relative reference](https://tools.ietf.org/html/rfc3986#section-4.2)
/// [rfc3986-3.3]: https://tools.ietf.org/html/rfc3986#section-3.3
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RelativeDIDURLPath {
    /// `path-absolute` from [RFC 3986 - 3.3. Path][rfc3986-3.3]
    Absolute(String),
    /// `path-noscheme` from [RFC 3986 - 3.3. Path][rfc3986-3.3]
    NoScheme(String),
    /// `path-empty` from [RFC 3986 - 3.3. Path][rfc3986-3.3]
    Empty,
}

/// [Relative DID URL](https://w3c.github.io/did-core/#relative-did-urls)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct RelativeDIDURL {
    pub path: RelativeDIDURLPath,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Builder, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[builder(
    setter(into, strip_option),
    default,
    build_fn(validate = "Self::validate")
)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>, // TODO: URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<OneOrMany<DID>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // publicKey is used by legacy DID documents
    pub public_key: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Context {
    URI(String),
    Object(Map<String, Value>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethodMap {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    pub controller: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    // TODO: make sure this JWK does not have private key material
    pub public_key_jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // TODO: make Base58 type like Base64urlUIntString
    pub public_key_base58: Option<String>,
    // TODO: ensure that not both key parameters are set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_account_id: Option<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum VerificationMethod {
    DIDURL(DIDURL),
    RelativeDIDURL(RelativeDIDURL),
    Map(VerificationMethodMap),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ServiceEndpoint {
    URI(String),
    Map(Value),
}

// <https://w3c.github.io/did-core/#service-properties>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>, // TODO: set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<OneOrMany<ServiceEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// An object from a DID Document returned by DID URL dereferencing
#[derive(Debug, Serialize, Clone, PartialEq)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Resource {
    VerificationMethod(VerificationMethodMap),
    Object(Map<String, Value>),
}

/// Something that can be used to derive a DID
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Source<'a> {
    /// Public key
    Key(&'a JWK),
    /// Public key and additional pattern
    KeyAndPattern(&'a JWK, &'a str),
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// <https://w3c.github.io/did-core/#did-parameters>
pub struct DIDParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // ASCII
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    pub relative_ref: Option<String>, // ASCII, percent-encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>, // ASCII
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<DateTime<Utc>>, // ASCII
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>, // ASCII
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDMethod: DIDResolver {
    /// Get the DID method name.
    /// <https://w3c.github.io/did-core/#method-schemes>
    fn name(&self) -> &'static str;

    // TODO: allow returning errors
    /// Generate a DID from some source
    fn generate(&self, _source: &Source) -> Option<String> {
        None
    }

    /// Upcast the DID method as a DID resolver.
    ///
    /// This is a workaround for [not being able to cast a trait object to a supertrait object](https://github.com/rust-lang/rfcs/issues/2765).
    ///
    /// Implementations should simply return `self`.
    fn to_resolver(&self) -> &dyn DIDResolver;
}

/// A collection of DID methods
#[derive(Clone, Default)]
pub struct DIDMethods<'a> {
    pub methods: HashMap<&'a str, &'a dyn DIDMethod>,
}

impl<'a> DIDMethods<'a> {
    /// Add a DID method to the set. Returns the previous one set for the given method name, if any.
    pub fn insert(&mut self, method: &'a dyn DIDMethod) -> Option<&'a dyn DIDMethod> {
        let name = method.name();
        self.methods.insert(name, method)
    }

    /// Get a DID method from the set.
    pub fn get(&self, method_name: &str) -> Option<&&'a dyn DIDMethod> {
        self.methods.get(method_name)
    }

    pub fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }

    /// Get DID method to handle a given DID
    pub fn get_method(&self, did: &str) -> Result<&&'a dyn DIDMethod, &'static str> {
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

    /// Generate a DID given some input
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
        method.resolve(did, input_metadata).await
    }

    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        let method = match self.get_method(did) {
            Ok(method) => method,
            Err(err) => return (ResolutionMetadata::from_error(err), Vec::new(), None),
        };
        method.resolve_representation(did, input_metadata).await
    }

    async fn dereference(
        &self,
        did_url: &DIDURL,
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
        method.dereference(did_url, input_metadata).await
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
            query: self.query.as_ref().map(|x| x.clone()),
            fragment: self.fragment.as_ref().map(|x| x.clone()),
        })
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
            query: self.query.as_ref().map(|x| x.clone()),
            fragment: self.fragment.as_ref().map(|x| x.clone()),
        }
    }
}

impl VerificationMethod {
    /// Return a DID URL for this verification method, given a DID as base URI
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
}

impl FromStr for DIDURL {
    type Err = Error;
    fn from_str(didurl: &str) -> Result<Self, Self::Err> {
        if !didurl.starts_with("did:") {
            return Err(Error::DIDURL);
        }
        let mut parts = didurl.splitn(2, '#');
        let before_fragment = parts.next().unwrap().to_string();
        let fragment = parts.next().map(|x| x.to_owned());
        let mut parts = before_fragment.splitn(2, '?');
        let before_query = parts.next().unwrap().to_string();
        let query = parts.next().map(|x| x.to_owned());
        let (did, path_abempty) = match before_query.find('/') {
            Some(i) => match before_query.split_at(i) {
                (did, path_abempty) => (did.to_string(), path_abempty.to_string()),
            },
            None => (before_query, "".to_string()),
        };
        Ok(Self {
            did,
            path_abempty,
            query,
            fragment,
        })
    }
}

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

impl FromStr for RelativeDIDURLPath {
    type Err = Error;
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path.is_empty() {
            return Ok(Self::Empty);
        }
        if path.starts_with("/") {
            // path-absolute = "/" [ segment-nz *( "/" segment ) ]
            // segment-nz    = 1*pchar
            // segment       = *pchar
            if path.len() >= 2 {
                if path.chars().nth(1) == Some('/') {
                    // Beginning with "//" would make a scheme-relative URI.
                    return Err(Error::DIDURL);
                }
            }
            // TODO: validate segment and pchar
            return Ok(Self::Absolute(path.to_string()));
        } else {
            // path-noscheme = segment-nz-nc *( "/" segment )
            // segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
            let first_segment = path.splitn(2, '/').next().unwrap().to_string();
            if first_segment.contains(':') {
                // First path segment containing ":" would make an absolute URI.
                return Err(Error::DIDURL);
            }
            // TODO: validate segment-nz-nc and pchar more
            return Ok(Self::NoScheme(path.to_string()));
        }
    }
}

impl fmt::Display for DIDURL {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.did, self.path_abempty)?;
        if let Some(ref query) = self.query {
            write!(f, "?{}", query)?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

impl fmt::Display for RelativeDIDURL {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path.fmt(f)?;
        if let Some(ref query) = self.query {
            write!(f, "?{}", query)?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

impl fmt::Display for RelativeDIDURLPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => Ok(()),
            Self::Absolute(string) => string.fmt(f),
            Self::NoScheme(string) => string.fmt(f),
        }
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
        format!("{}", didurl)
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
    fn default() -> Self {
        Document::new("")
    }
}

impl Default for RelativeDIDURLPath {
    fn default() -> Self {
        Self::Empty
    }
}

impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = Error;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(Error::MissingContext),
            Some(Context::URI(uri)) => uri,
            Some(Context::Object(_)) => return Err(Error::InvalidContext),
        };
        if first_uri != DEFAULT_CONTEXT
            && first_uri != V0_11_CONTEXT
            && first_uri != ALT_DEFAULT_CONTEXT
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
    fn validate(&self) -> Result<(), Error> {
        // validate is called before defaults are assigned.
        // None means default will be used.
        if self.id == None || self.id == Some("".to_string()) {
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
                Context::URI(uri) => uri,
                Context::Object(_) => return Err(Error::InvalidContext),
            };
            if first_uri != DEFAULT_CONTEXT
                && first_uri != V0_11_CONTEXT
                && first_uri != ALT_DEFAULT_CONTEXT
            {
                return Err(Error::InvalidContext);
            }
        }
        Ok(())
    }
}

// When selecting a object from JSON-LD document, @context should be copied into the sub-document.
fn merge_context(dest_opt: &mut Option<Value>, source: &Contexts) {
    let source = OneOrMany::<Context>::from(source.clone());
    let dest = dest_opt.take().unwrap_or(Value::Null);
    let mut dest_array = match dest {
        Value::Array(array) => array,
        Value::Object(object) => vec![Value::Object(object)],
        _ => Vec::new(),
    };
    for context in source {
        let value = match context {
            Context::URI(uri) => Value::String(uri),
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
    pub fn new(id: &str) -> Document {
        Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_string())),
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

    pub fn from_json(json: &str) -> Result<Document, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn from_json_bytes(json: &[u8]) -> Result<Document, serde_json::Error> {
        serde_json::from_slice(json)
    }

    /// Select an object in the DID document.
    /// For the [DID URL dereferencing algorithm, Step 1.1](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary)
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
    /// For the [DID URL Dereferencing - Dereferencing the Primary Resource, Step
    /// 1.1](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary)
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
            rel => return Err(format!("Unsupported verification relationship: {:?}", rel)),
        };
        let vm_ids = vms.iter().flatten().map(|vm| vm.get_id(did)).collect();
        Ok(vm_ids)
    }

    pub fn to_representation(&self, content_type: &str) -> Result<Vec<u8>, Error> {
        match content_type {
            TYPE_DID_LD_JSON => Ok(serde_json::to_vec(self)?),
            _ => Err(Error::RepresentationNotSupported),
        }
    }
}

pub mod example {
    use crate::did::{DIDMethod, Document};
    use crate::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
    };
    use async_trait::async_trait;

    const DOC_JSON_FOO: &'static str = include_str!("../tests/did-example-foo.json");
    const DOC_JSON_BAR: &'static str = include_str!("../tests/did-example-bar.json");

    // For vc-test-suite
    const DOC_JSON_TEST_ISSUER: &'static str =
        include_str!("../tests/did-example-test-issuer.json");
    const DOC_JSON_TEST_HOLDER: &'static str =
        include_str!("../tests/did-example-test-holder.json");

    pub struct DIDExample;

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDMethod for DIDExample {
        fn name(&self) -> &'static str {
            return "example";
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
                "did:example:ebfeb1f712ebc6f1c276e12ec21" => DOC_JSON_TEST_HOLDER,
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
            .context(Contexts::One(Context::URI("example:bad".to_string())))
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
}
