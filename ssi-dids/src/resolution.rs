use std::collections::BTreeMap;

use async_trait::async_trait;
use iref::IriRefBuf;
use serde::{Deserialize, Serialize};

use crate::{
    document::{self, representation, InvalidData},
    Document, PrimaryDIDURL, DID, DIDURL,
};

mod composition;
mod dereference;

pub use composition::*;
pub use dereference::*;

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "http")]
pub use http::*;

/// Pseudo-media-type used when returning a URL from
/// [DID URL dereferencing](DIDResolver::dereference).
pub const MEDIA_TYPE_URL: &str = "text/url";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),

    #[error("DID document not found")]
    NotFound,

    #[error("no representation specified")]
    NoRepresentation,

    #[error(transparent)]
    UnknownRepresentation(#[from] representation::Unknown),

    #[error("DID representation `{0}` not supported")]
    RepresentationNotSupported(String),

    #[error(transparent)]
    InvalidData(InvalidData),

    #[error("invalid method specific identifier")]
    InvalidMethodSpecificId(String),

    #[error("DID resolver internal error: {0}")]
    Internal(Box<dyn Send + std::error::Error>),
}

/// A [DID resolver](https://www.w3.org/TR/did-core/#dfn-did-resolvers),
/// implementing the [DID Resolution](https://www.w3.org/TR/did-core/#did-resolution)
/// [algorithm](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) and
/// optionally [DID URL Dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDResolver: Sync {
    /// Returns a resolver for the given method name, if any.
    fn get_method(&self, method_name: &str) -> Option<&dyn DIDMethodResolver>;

    fn supports_method(&self, method_name: &str) -> bool {
        self.get_method(method_name).is_some()
    }

    /// Resolves a DID.
    ///
    /// Fetches the DID document referenced by the input DID using the given
    /// options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    async fn resolve(&self, did: &DID, options: Options) -> Result<Output, Error> {
        let output = self.resolve_representation(did, options).await?;
        match &output.metadata.content_type {
            None => Err(Error::NoRepresentation),
            Some(ty) => {
                let ty: representation::MediaType = ty.parse()?;
                output
                    .try_map(|bytes| Document::from_bytes(ty, &bytes))
                    .map_err(Error::InvalidData)
            }
        }
    }

    /// Resolves a DID representation.
    ///
    /// Fetches the DID document representation referenced by the input DID
    /// using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    async fn resolve_representation(
        &self,
        did: &DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        match self.get_method(did.method_name()) {
            Some(m) => {
                m.resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            None => Err(Error::MethodNotSupported(did.method_name().to_string())),
        }
    }

    /// Dereference a DID URL to retrieve the primary content.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    async fn dereference_primary<'a>(
        &self,
        primary_did_url: &PrimaryDIDURL,
        options: &DerefOptions,
    ) -> Result<DerefOutput<PrimaryContent>, DerefError> {
        // 2
        let resolve_options: Options = match primary_did_url.query() {
            Some(query) => serde_urlencoded::from_str(query.as_str()).unwrap(),
            None => Options::default(),
        };
        let parameters = resolve_options.parameters.clone();
        let resolution_output = self.resolve(primary_did_url.did(), resolve_options).await?;

        // 3
        dereference_primary_resource(
            self,
            primary_did_url,
            parameters,
            options,
            resolution_output,
        )
        .await
    }

    /// Dereference a DID URL.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    async fn dereference(
        &self,
        did_url: &DIDURL,
        options: &DerefOptions,
    ) -> Result<DerefOutput, DerefError> {
        let (primary_did_url, fragment) = did_url.without_fragment();
        let primary_deref_output = self.dereference_primary(primary_did_url, options).await?;

        // 4
        match fragment {
            Some(fragment) => dereference_secondary_resource(
                primary_did_url,
                fragment,
                options,
                primary_deref_output,
            ),
            None => Ok(primary_deref_output.cast()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDMethodResolver: Send + Sync {
    /// Returns the name of the method handled by this resolver.
    fn method_name(&self) -> &str;

    /// Resolves a DID representation using a method specific identifier.
    ///
    /// Fetches the DID document representation referenced by the input method
    /// specific identifier using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    async fn resolve_method_representation(
        &self,
        method_specific_id: &str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a, T: DIDMethodResolver> DIDMethodResolver for &'a T {
    fn method_name(&self) -> &str {
        T::method_name(*self)
    }

    async fn resolve_method_representation(
        &self,
        method_specific_id: &str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        T::resolve_method_representation(*self, method_specific_id, options).await
    }
}

impl<T: DIDMethodResolver> DIDResolver for T {
    fn get_method(&self, method_name: &str) -> Option<&dyn DIDMethodResolver> {
        if self.method_name() == method_name {
            Some(self)
        } else {
            None
        }
    }
}

pub struct Output<T = document::Represented> {
    pub document: T,
    pub document_metadata: document::Metadata,
    pub metadata: Metadata,
}

impl<T> Output<T> {
    pub fn new(document: T, document_metadata: document::Metadata, metadata: Metadata) -> Self {
        Self {
            document,
            document_metadata,
            metadata,
        }
    }

    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<Output<U>, E> {
        Ok(Output {
            document: f(self.document)?,
            document_metadata: self.document_metadata,
            metadata: self.metadata,
        })
    }
}

/// Resolution input metadata.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Options {
    /// Preferred Media Type of the resolved DID document.
    ///
    /// [`accept`](https://www.w3.org/TR/did-spec-registries/#accept) resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<representation::MediaType>,

    /// DID parameters.
    #[serde(flatten)]
    pub parameters: Parameters,
}

/// DID parameters.
///
/// As specified in DID Core and/or in [DID Specification Registries][1].
///
/// [1]: https://www.w3.org/TR/did-spec-registries/#parameters
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    /// Service ID from the DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // TODO must be an ASCII string.

    /// Resource at a service endpoint, which is selected from a
    /// DID document by using the service parameter.
    #[serde(skip_serializing_if = "Option::is_none", alias = "relative-ref")]
    pub relative_ref: Option<IriRefBuf>, // TODO must be an relative URI reference according to <https://www.rfc-editor.org/rfc/rfc3986#section-4.2>.

    /// Specific version of a DID document to be resolved (the version ID could
    /// be sequential, or a UUID, or method-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>, // TODO must be an ASCII string.

    /// Version timestamp of a DID document to be resolved. That is, the DID
    /// document that was valid for a DID at a certain time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>, // TODO must be an `xsd:string` literal value.

    /// Resource hash of the DID document to add integrity protection, as
    /// specified in [HASHLINK](https://www.w3.org/TR/did-core/#bib-hashlink).
    ///
    /// This parameter is non-normative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hl: Option<String>, // TODO must be an ASCII string.

    /// Additional parameters.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Parameter>,
}

/// Arbitrary DID parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Parameter {
    Null,
    String(String),
    List(Vec<String>),
}

/// Resolution output metadata.
#[derive(Debug, Default)]
pub struct Metadata {
    content_type: Option<String>,
}

impl Metadata {
    pub fn from_content_type(content_type: Option<String>) -> Self {
        Self { content_type }
    }
}
