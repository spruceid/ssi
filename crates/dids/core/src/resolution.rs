use std::collections::BTreeMap;

use iref::IriRefBuf;
use serde::{Deserialize, Serialize};

use crate::{
    document::{self, representation, DIDVerificationMethod, InvalidData},
    DIDMethod, Document, PrimaryDIDURL, VerificationMethodDIDResolver, DID, DIDURL,
};

mod composition;
mod dereference;
mod static_resolver;

pub use dereference::*;
pub use static_resolver::StaticDIDResolver;

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "http")]
pub use http::*;

/// Pseudo-media-type used when returning a URL from
/// [DID URL dereferencing](DIDResolver::dereference).
pub const MEDIA_TYPE_URL: &str = "text/url";

/// DID resolution error.
///
/// Error raised by the [`DIDResolver::resolve`] method.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),

    /// DID document could not be found.
    #[error("DID document not found")]
    NotFound,

    /// Resolver doesn't know what representation to use for the DID document.
    #[error("no representation specified")]
    NoRepresentation,

    /// Requested DID document representation is not supported.
    #[error("DID representation `{0}` not supported")]
    RepresentationNotSupported(String),

    /// Invalid data provided to the resolver.
    #[error(transparent)]
    InvalidData(InvalidData),

    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),

    /// Invalid resolution options.
    #[error("invalid options")]
    InvalidOptions,

    /// Internal resolver-specific error.
    #[error("DID resolver internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Creates a new internal error.
    pub fn internal(error: impl ToString) -> Self {
        Self::Internal(error.to_string())
    }

    /// Returns the error kind.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::MethodNotSupported(_) => ErrorKind::MethodNotSupported,
            Self::NotFound => ErrorKind::NotFound,
            Self::NoRepresentation => ErrorKind::NoRepresentation,
            Self::RepresentationNotSupported(_) => ErrorKind::RepresentationNotSupported,
            Self::InvalidData(_) => ErrorKind::InvalidData,
            Self::InvalidMethodSpecificId(_) => ErrorKind::InvalidMethodSpecificId,
            Self::InvalidOptions => ErrorKind::InvalidOptions,
            Self::Internal(_) => ErrorKind::Internal,
        }
    }
}

impl From<representation::Unknown> for Error {
    fn from(value: representation::Unknown) -> Self {
        Self::RepresentationNotSupported(value.0)
    }
}

/// Resolution error kind.
///
/// Each resolution [`Error`] has a kind provided by the [`Error::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorKind {
    MethodNotSupported,
    NotFound,
    NoRepresentation,
    RepresentationNotSupported,
    InvalidData,
    InvalidMethodSpecificId,
    InvalidOptions,
    Internal,
}

pub trait DIDResolverByMethod {
    type MethodResolver: DIDMethodResolver;

    /// Returns a resolver for the given method name, if any.
    fn get_method(&self, method_name: &str) -> Option<&Self::MethodResolver>;

    fn supports_method(&self, method_name: &str) -> bool {
        self.get_method(method_name).is_some()
    }
}

impl<T: DIDResolverByMethod> DIDResolver for T {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
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
}

/// [DID resolver](https://www.w3.org/TR/did-core/#dfn-did-resolvers).
///
/// Any type implementing the [DID Resolution](https://www.w3.org/TR/did-core/#did-resolution)
/// [algorithm](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm)
/// through the [`resolve`](DIDResolver::resolve) method
/// and the [DID URL Dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing)
/// algorithm through the [`dereference`](DIDResolver::dereference) method.
///
/// This library provides the [`AnyDidMethod`] that implements this trait
/// by grouping various DID method implementations.
///
/// [`AnyDidMethod`]: <../dids/struct.AnyDidMethod.html>
pub trait DIDResolver {
    /// Resolves a DID representation.
    ///
    /// Fetches the DID document representation referenced by the input DID
    /// using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    #[allow(async_fn_in_trait)]
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error>;

    /// Resolves a DID with the given options.
    ///
    /// Fetches the DID document referenced by the input DID using the given
    /// options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    #[allow(async_fn_in_trait)]
    async fn resolve_with<'a>(&'a self, did: &'a DID, options: Options) -> Result<Output, Error> {
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

    /// Resolves a DID.
    ///
    /// Fetches the DID document referenced by the input DID using the default
    /// options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    #[allow(async_fn_in_trait)]
    async fn resolve<'a>(&'a self, did: &'a DID) -> Result<Output, Error> {
        self.resolve_with(did, Options::default()).await
    }

    /// Resolves a DID and extracts one of the verification methods it defines.
    ///
    /// This will return the first verification method found, although users
    /// should not expect the DID documents to always list verification methods
    /// in the same order.
    ///
    /// See: [`Document::into_any_verification_method()`].
    #[allow(async_fn_in_trait)]
    async fn resolve_into_any_verification_method<'a>(
        &'a self,
        did: &'a DID,
    ) -> Result<Option<DIDVerificationMethod>, Error> {
        Ok(self
            .resolve(did)
            .await?
            .document
            .into_document()
            .into_any_verification_method())
    }

    /// Dereference a DID URL to retrieve the primary content.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    #[allow(async_fn_in_trait)]
    async fn dereference_primary<'a>(
        &'a self,
        primary_did_url: &'a PrimaryDIDURL,
    ) -> Result<DerefOutput<PrimaryContent>, DerefError> {
        self.dereference_primary_with(primary_did_url, Options::default())
            .await
    }

    /// Dereference a DID URL to retrieve the primary content.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    #[allow(async_fn_in_trait)]
    async fn dereference_primary_with<'a>(
        &'a self,
        primary_did_url: &'a PrimaryDIDURL,
        mut resolve_options: Options,
    ) -> Result<DerefOutput<PrimaryContent>, DerefError> {
        // 2
        resolve_options.extend(match primary_did_url.query() {
            Some(query) => serde_urlencoded::from_str(query.as_str()).unwrap(),
            None => Options::default(),
        });

        let parameters = resolve_options.parameters.clone();

        let resolution_output = self
            .resolve_with(primary_did_url.did(), resolve_options)
            .await?;

        dereference_primary_resource(self, primary_did_url, parameters, resolution_output).await
    }

    /// Dereference a DID URL with a path or query to retrieve the primary
    /// content.
    ///
    /// This function is called from [`Self::dereference_primary()`] only if
    /// the primary DID url has a path and/or query, and the query does not
    /// include any service.
    /// Users should always call [`Self::dereference_primary()`].
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    #[allow(async_fn_in_trait)]
    async fn dereference_primary_with_path_or_query<'a>(
        &'a self,
        _primary_did_url: &'a PrimaryDIDURL,
    ) -> Result<DerefOutput<PrimaryContent>, DerefError> {
        Err(DerefError::NotFound)
    }

    /// Dereference a DID URL.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    #[allow(async_fn_in_trait)]
    async fn dereference_with<'a>(
        &'a self,
        did_url: &'a DIDURL,
        options: Options,
    ) -> Result<DerefOutput, DerefError> {
        let (primary_did_url, fragment) = did_url.without_fragment();
        let primary_deref_output = self
            .dereference_primary_with(primary_did_url, options)
            .await?;
        // 4
        match fragment {
            Some(fragment) => {
                dereference_secondary_resource(primary_did_url, fragment, primary_deref_output)
            }
            None => Ok(primary_deref_output.cast()),
        }
    }

    /// Dereference a DID URL.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    #[allow(async_fn_in_trait)]
    async fn dereference<'a>(&'a self, did_url: &'a DIDURL) -> Result<DerefOutput, DerefError> {
        self.dereference_with(did_url, Options::default()).await
    }

    /// Turns this DID resolver into a verification method resolver.
    ///
    /// To resolve a verification method, the output resolver will first
    /// resolve the DID using the given `options` then pull the referenced
    /// method from the DID document.
    fn into_vm_resolver_with<M>(self, options: Options) -> VerificationMethodDIDResolver<Self, M>
    where
        Self: Sized,
    {
        VerificationMethodDIDResolver::new_with_options(self, options)
    }

    /// Turns this DID resolver into a verification method resolver.
    ///
    /// To resolve a verification method, the output resolver will first
    /// resolve the DID then pull the referenced method from the DID document.
    ///
    /// This is equivalent to calling
    /// [`into_vm_resolver_with`](DIDResolver::into_vm_resolver_with)
    /// with the default options.
    fn into_vm_resolver<M>(self) -> VerificationMethodDIDResolver<Self, M>
    where
        Self: Sized,
    {
        VerificationMethodDIDResolver::new(self)
    }
}

pub trait DIDMethodResolver: DIDMethod {
    /// Returns the name of the method handled by this resolver.
    fn method_name(&self) -> &str {
        Self::DID_METHOD_NAME
    }

    /// Resolves a DID representation using a method specific identifier.
    ///
    /// Fetches the DID document representation referenced by the input method
    /// specific identifier using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    #[allow(async_fn_in_trait)]
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error>;
}

impl<'a, T: DIDMethodResolver> DIDMethodResolver for &'a T {
    fn method_name(&self) -> &str {
        T::method_name(*self)
    }

    async fn resolve_method_representation<'b>(
        &'b self,
        method_specific_id: &'b str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        T::resolve_method_representation(*self, method_specific_id, options).await
    }
}

impl<T: DIDMethodResolver> DIDResolverByMethod for T {
    type MethodResolver = Self;

    fn get_method(&self, method_name: &str) -> Option<&Self> {
        if self.method_name() == method_name {
            Some(self)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct Output<T = document::Represented> {
    pub document: T,
    pub document_metadata: document::Metadata,
    pub metadata: Metadata,
}

impl<T> Output<T> {
    pub fn from_content(content: T, content_type: Option<String>) -> Self {
        Self::new(
            content,
            document::Metadata::default(),
            Metadata::from_content_type(content_type),
        )
    }

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

impl Options {
    pub fn extend(&mut self, other: Self) {
        if let Some(value) = other.accept {
            self.accept = Some(value)
        }

        self.parameters.extend(other.parameters)
    }
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

    /// Expected public key format (non-standard option).
    ///
    /// Defined by <https://w3c-ccg.github.io/did-method-key>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_format: Option<String>,

    /// Additional parameters.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Parameter>,
}

impl Parameters {
    pub fn extend(&mut self, other: Self) {
        if let Some(value) = other.service {
            self.service = Some(value)
        }

        if let Some(value) = other.relative_ref {
            self.relative_ref = Some(value)
        }

        if let Some(value) = other.version_id {
            self.version_id = Some(value)
        }

        if let Some(value) = other.version_time {
            self.version_time = Some(value)
        }

        if let Some(value) = other.hl {
            self.hl = Some(value)
        }

        if let Some(value) = other.public_key_format {
            self.public_key_format = Some(value)
        }

        self.additional.extend(other.additional);
    }
}

/// Arbitrary DID parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Parameter {
    Null,
    String(String),
    List(Vec<String>),
}

impl Parameter {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_string(self) -> Result<String, Self> {
        match self {
            Self::String(s) => Ok(s),
            other => Err(other),
        }
    }
}

/// Resolution output metadata.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub content_type: Option<String>,
}

impl Metadata {
    pub fn from_content_type(content_type: Option<String>) -> Self {
        Self { content_type }
    }
}
