use crate::{
    document,
    resolution::{self, DerefError},
};
use serde::Serialize;

#[derive(Serialize)]
pub enum ResolutionResult {
    Success {
        content: String,
        metadata: resolution::Metadata,
        document_metadata: document::Metadata,
    },
    Failure {
        error: ErrorCode,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidDid,
    NotFound,
    RepresentationNotSupported,
    MethodNotSupported,
    InternalError,
}

impl From<resolution::Error> for ErrorCode {
    fn from(value: resolution::Error) -> Self {
        match value {
            resolution::Error::MethodNotSupported(_) => Self::MethodNotSupported,
            resolution::Error::NotFound => Self::NotFound,
            resolution::Error::NoRepresentation => Self::InternalError,
            resolution::Error::RepresentationNotSupported(_) => Self::RepresentationNotSupported,
            resolution::Error::InvalidData(_) => Self::InternalError,
            resolution::Error::InvalidMethodSpecificId(_) => Self::InvalidDid,
            resolution::Error::InvalidOptions => Self::InternalError,
            resolution::Error::Internal(_) => Self::InternalError,
        }
    }
}

impl From<DerefError> for ErrorCode {
    fn from(value: DerefError) -> Self {
        match value {
            DerefError::Resolution(e) => e.into(),
            DerefError::MissingServiceEndpoint(_) => Self::InternalError,
            DerefError::UnsupportedServiceEndpointMap => Self::InternalError,
            DerefError::UnsupportedMultipleServiceEndpoints => Self::InternalError,
            DerefError::ServiceEndpointConstructionFailed(_) => Self::InternalError,
            DerefError::FragmentConflict => Self::InternalError,
            DerefError::NullDereference => Self::InternalError,
            DerefError::NotFound => Self::NotFound,
            DerefError::ResourceNotFound(_) => Self::NotFound,
        }
    }
}
