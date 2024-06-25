use crate::EncodedStatusMap;
use std::{borrow::Borrow, ops::Deref, sync::Arc};

mod cache;
pub use cache::Cached;

mod http;
pub use http::HttpClient;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("not found")]
    NotFound,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("missing media type")]
    MissingMediaType,

    #[error("invalid media type")]
    InvalidMediaType,

    #[error("{0}")]
    Encoded(String),

    #[error("decoding failed: {0}")]
    Decoding(String),
}

pub trait TypedStatusMapProvider<I: ?Sized, T: EncodedStatusMap> {
    #[allow(async_fn_in_trait)]
    async fn get_typed(&self, id: &I) -> Result<MaybeCached<T::Decoded>, ProviderError>;
}

pub trait StatusMapProvider<I: ?Sized> {
    #[allow(async_fn_in_trait)]
    async fn get<T: EncodedStatusMap>(
        &self,
        id: &I,
    ) -> Result<MaybeCached<T::Decoded>, ProviderError>
    where
        Self: TypedStatusMapProvider<I, T>,
    {
        self.get_typed(id).await
    }
}

pub enum MaybeCached<T> {
    Cached(Arc<T>),
    NotCached(T),
}

impl<T: Clone> MaybeCached<T> {
    pub fn into_owned(self) -> T {
        match self {
            Self::Cached(t) => T::clone(&t),
            Self::NotCached(t) => t,
        }
    }
}

impl<T> Borrow<T> for MaybeCached<T> {
    fn borrow(&self) -> &T {
        match self {
            Self::Cached(t) => t,
            Self::NotCached(t) => t,
        }
    }
}

impl<T> Deref for MaybeCached<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.borrow()
    }
}
