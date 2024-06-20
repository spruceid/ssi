use iref::{Uri, UriBuf};
use reqwest::{header, StatusCode};

use crate::{
    document::{self, representation::MediaType},
    DIDResolver, DID,
};

use super::{Error, Metadata, Output};

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// A DID Resolver implementing a client for the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
#[derive(Debug, Clone)]
pub struct HTTPDIDResolver {
    /// HTTP(S) URL for DID resolver HTTP(S) endpoint.
    endpoint: UriBuf,
}

impl HTTPDIDResolver {
    /// Construct a new HTTP DID Resolver with a given [endpoint][Self::endpoint] URL.
    pub fn new(url: &Uri) -> Self {
        Self {
            endpoint: url.to_owned(),
        }
    }

    pub fn endpoint(&self) -> &Uri {
        &self.endpoint
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("unable to initialize HTTP client")]
    Initialization,

    #[error("HTTP error: {0}")]
    Reqwest(reqwest::Error),

    #[error("HTTP server returned error code {0}")]
    Error(StatusCode),

    #[error("missing content-type header")]
    MissingContentType,

    #[error("content type mismatch")]
    ContentTypeMismatch,

    #[error("invalid content type")]
    InvalidContentType,
}

impl DIDResolver for HTTPDIDResolver {
    /// Resolve a DID over HTTP(S), using the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: super::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let query = serde_urlencoded::to_string(&options.parameters).unwrap();

        let did_urlencoded =
            percent_encoding::utf8_percent_encode(did, percent_encoding::CONTROLS).to_string();

        let mut url = self.endpoint.to_string() + &did_urlencoded;
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query)
        }

        let url: reqwest::Url = url.parse().unwrap();

        let client = reqwest::Client::builder()
            .build()
            .map_err(|_| Error::internal(InternalError::Initialization))?;

        let mut request = client.get(url);
        if let Some(accept) = options.accept {
            request = request.header("Accept", accept.to_string());
        }

        let response = request
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(|e| Error::internal(InternalError::Reqwest(e)))?;

        match response.status() {
            StatusCode::OK => {
                let content_type: Option<String> =
                    match (response.headers().get(header::CONTENT_TYPE), options.accept) {
                        (Some(content_type), Some(accept)) => {
                            if content_type == accept.name() {
                                Some(accept.name().to_string())
                            } else {
                                return Err(Error::internal(InternalError::ContentTypeMismatch));
                            }
                        }
                        (Some(content_type), None) => Some(
                            content_type
                                .to_str()
                                .map_err(|_| Error::internal(InternalError::InvalidContentType))?
                                .to_string(),
                        ),
                        (None, Some(_)) => {
                            return Err(Error::internal(InternalError::MissingContentType))
                        }
                        (None, None) => None,
                    };

                Ok(Output::new(
                    response
                        .bytes()
                        .await
                        .map_err(|e| Error::internal(InternalError::Reqwest(e)))?
                        .to_vec(),
                    document::Metadata::default(),
                    Metadata::from_content_type(content_type),
                ))
            }
            StatusCode::NOT_FOUND => Err(Error::NotFound),
            StatusCode::NOT_IMPLEMENTED => {
                Err(Error::MethodNotSupported(did.method_name().to_string()))
            }
            StatusCode::VARIANT_ALSO_NEGOTIATES => Err(Error::RepresentationNotSupported(
                options
                    .accept
                    .map(MediaType::into_name)
                    .unwrap_or_default()
                    .to_string(),
            )),
            error_code => Err(Error::internal(InternalError::Error(error_code))),
        }
    }
}
