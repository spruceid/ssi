use iref::{Iri, IriBuf};
use ssi_core::one_or_many::OneOrMany;

use crate::{
    document::{self, representation, service, DIDVerificationMethod, Represented, Resource},
    DIDURLBuf, Fragment, PrimaryDIDURL, DIDURL,
};

use super::{DIDResolver, Error, Metadata, Output, Parameters, MEDIA_TYPE_URL};

#[derive(Debug, thiserror::Error)]
pub enum DerefError {
    #[error("DID resolution failed: {0}")]
    Resolution(#[from] Error),

    #[error("missing service endpoint `{0}`")]
    MissingServiceEndpoint(String),

    #[error("unsupported service endpoint map")]
    UnsupportedServiceEndpointMap,

    #[error("unsupported multiple service endpoints")]
    UnsupportedMultipleServiceEndpoints,

    #[error("service endpoint construction failed: {0}")]
    ServiceEndpointConstructionFailed(#[from] ServiceEndpointConstructionConflict),

    #[error("both the DID URL and input service endpoint URL have a fragment component")]
    FragmentConflict,

    #[error("tried to dereference null primary content")]
    NullDereference,

    #[error("DID document not found")]
    NotFound,

    #[error("could not find resource `{0}` in DID document")]
    ResourceNotFound(DIDURLBuf),
}

pub struct DerefOutput<T = Content> {
    pub content: T,
    pub content_metadata: document::Metadata,
    pub metadata: Metadata,
}

impl<T> DerefOutput<T> {
    pub fn new(content: T, content_metadata: document::Metadata, metadata: Metadata) -> Self {
        Self {
            content,
            content_metadata,
            metadata,
        }
    }

    pub fn url(url: IriBuf) -> Self
    where
        T: From<IriBuf>,
    {
        Self::new(
            url.into(),
            document::Metadata::default(),
            Metadata::from_content_type(Some(MEDIA_TYPE_URL.to_string())),
        )
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> DerefOutput<U> {
        DerefOutput {
            content: f(self.content),
            content_metadata: self.content_metadata,
            metadata: self.metadata,
        }
    }

    pub fn cast<U: From<T>>(self) -> DerefOutput<U> {
        self.map(T::into)
    }

    pub fn into_content(self) -> T {
        self.content
    }
}

impl DerefOutput<PrimaryContent> {
    pub fn null() -> Self {
        Self::new(
            PrimaryContent::Null,
            document::Metadata::default(),
            Metadata::default(),
        )
    }
}

pub enum PrimaryContent {
    Null,
    Url(IriBuf), // TODO must be an URL
    Document(document::Represented),
}

impl From<IriBuf> for PrimaryContent {
    fn from(value: IriBuf) -> Self {
        Self::Url(value)
    }
}

#[derive(Debug)]
pub enum Content {
    Null,
    Url(IriBuf), // TODO must be an URL
    Resource(Resource),
}

impl Content {
    pub fn as_verification_method(&self) -> Option<&DIDVerificationMethod> {
        match self {
            Self::Resource(r) => r.as_verification_method(),
            _ => None,
        }
    }

    pub fn into_verification_method(self) -> Result<DIDVerificationMethod, Self> {
        match self {
            Self::Resource(r) => r.into_verification_method().map_err(Self::Resource),
            other => Err(other),
        }
    }
}

impl From<PrimaryContent> for Content {
    fn from(value: PrimaryContent) -> Self {
        match value {
            PrimaryContent::Null => Self::Null,
            PrimaryContent::Url(url) => Self::Url(url),
            PrimaryContent::Document(doc) => {
                Self::Resource(Resource::Document(doc.into_document()))
            }
        }
    }
}

/// [Dereferencing the Primary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
pub(crate) async fn dereference_primary_resource<'a, R: ?Sized + DIDResolver>(
    resolver: &'a R,
    primary_did_url: &'a PrimaryDIDURL,
    parameters: Parameters,
    resolution_output: Output,
) -> Result<DerefOutput<PrimaryContent>, DerefError> {
    // 1
    match &parameters.service {
        Some(id) => {
            // 1.1
            match resolution_output.document.service(id) {
                Some(service) => {
                    // 1.2, 1.2.1
                    // TODO: support these other cases?
                    let input_service_endpoint_url = match &service.service_endpoint {
                        None => return Err(DerefError::MissingServiceEndpoint(id.clone())),
                        Some(OneOrMany::One(service::Endpoint::Uri(uri))) => uri.as_iri(),
                        Some(OneOrMany::One(service::Endpoint::Map(_))) => {
                            return Err(DerefError::UnsupportedServiceEndpointMap)
                        }
                        Some(OneOrMany::Many(_)) => {
                            return Err(DerefError::UnsupportedMultipleServiceEndpoints)
                        }
                    };

                    // 1.2.2, 1.2.3
                    let r = construct_service_endpoint(
                        primary_did_url,
                        &parameters,
                        input_service_endpoint_url,
                    );

                    match r {
                        Ok(output_service_endpoint_url) => {
                            // 1.3
                            Ok(DerefOutput::url(output_service_endpoint_url))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                None => Err(DerefError::MissingServiceEndpoint(id.clone())),
            }
        }
        None => {
            // 2
            if primary_did_url.path().is_empty() && primary_did_url.query().is_none() {
                // 2.1
                return Ok(DerefOutput::new(
                    PrimaryContent::Document(resolution_output.document),
                    document::Metadata::default(),
                    resolution_output.metadata,
                ));
            }

            // 3
            if !primary_did_url.path().is_empty() || primary_did_url.query().is_some() {
                return resolver
                    .dereference_primary_with_path_or_query(primary_did_url)
                    .await;
            }

            // 4
            Err(DerefError::NotFound)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceEndpointConstructionConflict {
    #[error("both the DID URL and `relativeRef` parameter have a path component")]
    Path,

    #[error("both the DID URL and input service endpoint URL have a query component")]
    Query,

    #[error("both the DID URL and input service endpoint URL have a fragment component")]
    Fragment,
}

/// <https://w3c-ccg.github.io/did-resolution/#service-endpoint-construction>
fn construct_service_endpoint(
    did_url: &DIDURL,
    did_parameters: &Parameters,
    service_endpoint_url: &Iri,
) -> Result<IriBuf, ServiceEndpointConstructionConflict> {
    // https://w3c-ccg.github.io/did-resolution/#algorithm
    let mut output = IriBuf::from_scheme(service_endpoint_url.scheme().to_owned());
    output.set_authority(service_endpoint_url.authority());
    output.set_path(service_endpoint_url.path());

    let relative_ref_path = did_parameters
        .relative_ref
        .as_ref()
        .map(|r| r.path())
        .unwrap_or("".try_into().unwrap());
    match (did_url.path().is_empty(), relative_ref_path.is_empty()) {
        (false, true) => output.set_path(did_url.path().as_str().try_into().unwrap()),
        (true, false) => output.set_path(relative_ref_path),
        (false, false) => return Err(ServiceEndpointConstructionConflict::Path),
        (true, true) => (),
    }

    match (did_url.query(), service_endpoint_url.query()) {
        (Some(query), None) => output.set_query(Some(query.as_str().try_into().unwrap())),
        (None, Some(query)) => output.set_query(Some(query)),
        (Some(_), Some(_)) => return Err(ServiceEndpointConstructionConflict::Query),
        (None, None) => (),
    }

    match (did_url.fragment(), service_endpoint_url.fragment()) {
        (Some(fragment), None) => output.set_fragment(Some(fragment.as_str().try_into().unwrap())),
        (None, Some(fragment)) => output.set_fragment(Some(fragment)),
        (Some(_), Some(_)) => return Err(ServiceEndpointConstructionConflict::Fragment),
        (None, None) => (),
    }

    Ok(output)
}

impl Represented {
    pub fn dereference_secondary_resource(
        self,
        primary_did_url: &PrimaryDIDURL,
        fragment: &Fragment,
        content_metadata: document::Metadata,
        metadata: Metadata,
    ) -> Result<DerefOutput, DerefError> {
        match self {
            Self::Json(d) => d.dereference_secondary_resource(
                primary_did_url,
                fragment,
                content_metadata,
                metadata,
            ),
            Self::JsonLd(d) => d.dereference_secondary_resource(
                primary_did_url,
                fragment,
                content_metadata,
                metadata,
            ),
        }
    }
}

impl representation::Json {
    pub fn dereference_secondary_resource(
        self,
        primary_did_url: &PrimaryDIDURL,
        fragment: &Fragment,
        content_metadata: document::Metadata,
        metadata: Metadata,
    ) -> Result<DerefOutput, DerefError> {
        let id = primary_did_url.to_owned().with_fragment(fragment);
        match self.into_document().into_resource(&id) {
            Some(resource) => Ok(DerefOutput::new(
                Content::Resource(resource),
                content_metadata,
                metadata,
            )),
            None => Err(DerefError::ResourceNotFound(id)),
        }
    }
}

impl representation::JsonLd {
    pub fn dereference_secondary_resource(
        self,
        primary_did_url: &PrimaryDIDURL,
        fragment: &Fragment,
        content_metadata: document::Metadata,
        metadata: Metadata,
    ) -> Result<DerefOutput, DerefError> {
        // TODO: use actual JSON-LD fragment dereferencing
        // https://www.w3.org/TR/did-core/#application-did-ld-json
        //   Fragment identifiers used with application/did+ld+json are treated according to the
        //   rules associated with the JSON-LD 1.1: application/ld+json media type [JSON-LD11].
        let id = primary_did_url.to_owned().with_fragment(fragment);
        match self.into_document().into_resource(&id) {
            Some(resource) => Ok(DerefOutput::new(
                Content::Resource(resource),
                content_metadata,
                metadata,
            )),
            None => Err(DerefError::ResourceNotFound(id)),
        }
    }
}

/// [Dereferencing the Secondary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
pub(crate) fn dereference_secondary_resource(
    primary_did_url: &PrimaryDIDURL,
    fragment: &Fragment,
    primary_deref_output: DerefOutput<PrimaryContent>,
) -> Result<DerefOutput, DerefError> {
    // 1
    match primary_deref_output.content {
        PrimaryContent::Document(doc) => doc.dereference_secondary_resource(
            primary_did_url,
            fragment,
            primary_deref_output.content_metadata,
            primary_deref_output.metadata,
        ),
        PrimaryContent::Url(mut url) => {
            // 2
            // 2.1
            if url.fragment().is_some() {
                Err(DerefError::FragmentConflict)
            } else {
                url.set_fragment(Some(fragment.as_str().try_into().unwrap()));
                Ok(DerefOutput::new(
                    Content::Url(url),
                    primary_deref_output.content_metadata,
                    primary_deref_output.metadata,
                ))
            }
        }
        PrimaryContent::Null => Err(DerefError::NullDereference),
    }
}
