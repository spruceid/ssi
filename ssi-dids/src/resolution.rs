use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task;

use iref::IriRefBuf;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};

use crate::{
    document::{self, representation, InvalidData},
    Document, Fragment, PrimaryDIDURL, DID, DIDURL,
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

    #[error("invalid options")]
    InvalidOptions,

    #[error("DID resolver internal error: {0}")]
    Internal(Box<DynInternalError>),
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::MethodNotSupported(_) => ErrorKind::MethodNotSupported,
            Self::NotFound => ErrorKind::NotFound,
            Self::NoRepresentation => ErrorKind::NoRepresentation,
            Self::UnknownRepresentation(_) => ErrorKind::UnknownRepresentation,
            Self::RepresentationNotSupported(_) => ErrorKind::RepresentationNotSupported,
            Self::InvalidData(_) => ErrorKind::InvalidData,
            Self::InvalidMethodSpecificId(_) => ErrorKind::InvalidMethodSpecificId,
            Self::InvalidOptions => ErrorKind::InvalidOptions,
            Self::Internal(_) => ErrorKind::Internal
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type DynInternalError = dyn Send + std::error::Error;

#[cfg(target_arch = "wasm32")]
pub type DynInternalError = dyn std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorKind {
    MethodNotSupported,
    NotFound,
    NoRepresentation,
    UnknownRepresentation,
    RepresentationNotSupported,
    InvalidData,
    InvalidMethodSpecificId,
    InvalidOptions,
    Internal
}

#[pin_project]
pub struct Resolve<'a, T: 'a + ?Sized + DIDResolver> {
    #[pin]
    inner: T::ResolveRepresentation<'a>,
}

impl<'a, T: 'a + ?Sized + DIDResolver> Resolve<'a, T> {
    fn new(f: T::ResolveRepresentation<'a>) -> Self {
        Self { inner: f }
    }
}

impl<'a, T: ?Sized + DIDResolver> Future for Resolve<'a, T> {
    type Output = Result<Output, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx).map(|result| {
            result.and_then(|output| match &output.metadata.content_type {
                None => Err(Error::NoRepresentation),
                Some(ty) => {
                    let ty: representation::MediaType = ty.parse()?;
                    output
                        .try_map(|bytes| Document::from_bytes(ty, &bytes))
                        .map_err(Error::InvalidData)
                }
            })
        })
    }
}

#[pin_project]
pub struct DereferencePrimary<'a, T: ?Sized + DIDResolver> {
    resolver: &'a T,

    primary_did_url: &'a PrimaryDIDURL,

    parameters: Option<Parameters>,

    options: &'a DerefOptions,

    #[pin]
    resolution: Resolve<'a, T>,

    #[pin]
    dereference: Option<DereferencePrimaryResource<'a, T>>,
}

impl<'a, T: ?Sized + DIDResolver> DereferencePrimary<'a, T> {
    fn new(
        resolver: &'a T,
        primary_did_url: &'a PrimaryDIDURL,
        parameters: Parameters,
        options: &'a DerefOptions,
        resolution: Resolve<'a, T>,
    ) -> Self {
        Self {
            resolver,
            primary_did_url,
            parameters: Some(parameters),
            options,
            resolution,
            dereference: None,
        }
    }
}

impl<'a, T: ?Sized + DIDResolver> Future for DereferencePrimary<'a, T> {
    type Output = Result<DerefOutput<PrimaryContent>, DerefError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut this = self.project();
        if this.dereference.is_none() {
            match this.resolution.poll(cx) {
                task::Poll::Ready(Ok(resolution_output)) => {
                    // 3
                    this.dereference.set(Some(dereference_primary_resource::<T>(
                        this.resolver,
                        this.primary_did_url,
                        this.parameters.take().unwrap(),
                        this.options,
                        resolution_output,
                    )))
                }
                task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e.into())),
                task::Poll::Pending => return task::Poll::Pending,
            }
        }

        let dereference = this.dereference.as_pin_mut().unwrap();
        dereference.poll(cx)
    }
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
    type ResolveRepresentation<'a> = ResolveRepresentationByMethod<'a, T::MethodResolver> where Self: 'a;

    fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Self::ResolveRepresentation<'a> {
        match self.get_method(did.method_name()) {
            Some(m) => ResolveRepresentationByMethod::pending(
                m.resolve_method_representation(did.method_specific_id(), options),
            ),
            None => ResolveRepresentationByMethod::err(Error::MethodNotSupported(
                did.method_name().to_string(),
            )),
        }
    }
}

#[pin_project]
pub struct ResolveRepresentationByMethod<'a, M: 'a + ?Sized + DIDMethodResolver> {
    #[pin]
    inner: ResolveRepresentationByMethodInner<'a, M>,
}

impl<'a, M: ?Sized + DIDMethodResolver> ResolveRepresentationByMethod<'a, M> {
    fn pending(f: M::ResolveMethodRepresentation<'a>) -> Self {
        Self {
            inner: ResolveRepresentationByMethodInner::Pending(f),
        }
    }

    fn err(e: Error) -> Self {
        Self {
            inner: ResolveRepresentationByMethodInner::Err(Some(e)),
        }
    }
}

#[pin_project(project = ResolveRepresentationByMethodProj)]
pub enum ResolveRepresentationByMethodInner<'a, M: 'a + ?Sized + DIDMethodResolver> {
    Err(Option<Error>),
    Pending(#[pin] M::ResolveMethodRepresentation<'a>),
}

impl<'a, M: ?Sized + DIDMethodResolver> Future for ResolveRepresentationByMethod<'a, M> {
    type Output = Result<Output<Vec<u8>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        match this.inner.project() {
            ResolveRepresentationByMethodProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
            ResolveRepresentationByMethodProj::Pending(f) => f.poll(cx),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type BoxedResolveRepresentation<'a> =
    Pin<Box<dyn 'a + Send + Future<Output = Result<Output<Vec<u8>>, Error>>>>;
#[cfg(target_arch = "wasm32")]
pub type BoxedResolveRepresentation<'a> =
    Pin<Box<dyn 'a + Future<Output = Result<Output<Vec<u8>>, Error>>>>;

/// A [DID resolver](https://www.w3.org/TR/did-core/#dfn-did-resolvers),
/// implementing the [DID Resolution](https://www.w3.org/TR/did-core/#did-resolution)
/// [algorithm](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) and
/// optionally [DID URL Dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing).
pub trait DIDResolver {
    /// Future returned by the `resolve_representation` method.
    type ResolveRepresentation<'a>: 'a + Future<Output = Result<Output<Vec<u8>>, Error>>
    where
        Self: 'a;

    /// Resolves a DID representation.
    ///
    /// Fetches the DID document representation referenced by the input DID
    /// using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Self::ResolveRepresentation<'a>;

    /// Resolves a DID.
    ///
    /// Fetches the DID document referenced by the input DID using the given
    /// options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    fn resolve<'a>(&'a self, did: &'a DID, options: Options) -> Resolve<Self> {
        Resolve::new(self.resolve_representation(did, options))
    }

    /// Dereference a DID URL to retrieve the primary content.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    fn dereference_primary<'a>(
        &'a self,
        primary_did_url: &'a PrimaryDIDURL,
        options: &'a DerefOptions,
    ) -> DereferencePrimary<'a, Self> {
        // 2
        let resolve_options: Options = match primary_did_url.query() {
            Some(query) => serde_urlencoded::from_str(query.as_str()).unwrap(),
            None => Options::default(),
        };

        let parameters = resolve_options.parameters.clone();

        DereferencePrimary::new(
            self,
            primary_did_url,
            parameters,
            options,
            self.resolve(primary_did_url.did(), resolve_options),
        )
    }

    /// Dereference a DID URL.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-url-dereferencing>
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
    fn dereference<'a>(
        &'a self,
        did_url: &'a DIDURL,
        options: &'a DerefOptions,
    ) -> Dereference<'a, Self> {
        let (primary_did_url, fragment) = did_url.without_fragment();
        Dereference::new(
            primary_did_url,
            fragment,
            options,
            self.dereference_primary(primary_did_url, options),
        )
    }
}

#[pin_project]
pub struct Dereference<'a, T: ?Sized + DIDResolver> {
    primary_did_url: &'a PrimaryDIDURL,

    fragment: Option<&'a Fragment>,

    options: &'a DerefOptions,

    #[pin]
    dereference_primary: DereferencePrimary<'a, T>,
}

impl<'a, T: ?Sized + DIDResolver> Dereference<'a, T> {
    pub fn new(
        primary_did_url: &'a PrimaryDIDURL,
        fragment: Option<&'a Fragment>,
        options: &'a DerefOptions,
        dereference_primary: DereferencePrimary<'a, T>,
    ) -> Self {
        Self {
            primary_did_url,
            fragment,
            options,
            dereference_primary,
        }
    }
}

impl<'a, T: ?Sized + DIDResolver> Future for Dereference<'a, T> {
    type Output = Result<DerefOutput, DerefError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.dereference_primary.poll(cx).map(|result| {
            result.and_then(|primary_deref_output| {
                // 4
                match this.fragment {
                    Some(fragment) => dereference_secondary_resource(
                        this.primary_did_url,
                        fragment,
                        this.options,
                        primary_deref_output,
                    ),
                    None => Ok(primary_deref_output.cast()),
                }
            })
        })
    }
}

pub trait DIDMethodResolver {
    type ResolveMethodRepresentation<'a>: 'a + Future<Output = Result<Output<Vec<u8>>, Error>>
    where
        Self: 'a;

    /// Returns the name of the method handled by this resolver.
    fn method_name(&self) -> &str;

    /// Resolves a DID representation using a method specific identifier.
    ///
    /// Fetches the DID document representation referenced by the input method
    /// specific identifier using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Self::ResolveMethodRepresentation<'a>;
}

impl<'a, T: DIDMethodResolver> DIDMethodResolver for &'a T {
    type ResolveMethodRepresentation<'b> = T::ResolveMethodRepresentation<'b> where Self: 'b;

    fn method_name(&self) -> &str {
        T::method_name(*self)
    }

    fn resolve_method_representation<'b>(
        &'b self,
        method_specific_id: &'b str,
        options: Options,
    ) -> Self::ResolveMethodRepresentation<'b> {
        T::resolve_method_representation(*self, method_specific_id, options)
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
#[derive(Debug, Default)]
pub struct Metadata {
    content_type: Option<String>,
}

impl Metadata {
    pub fn from_content_type(content_type: Option<String>) -> Self {
        Self { content_type }
    }
}
