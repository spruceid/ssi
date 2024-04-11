use crate::EncodedStatusMap;
use std::{borrow::Borrow, ops::Deref, sync::Arc};

mod cache;
pub use cache::Cached;

mod http;
pub use http::HttpClient;

pub enum ProviderError {
    NotFound,
    Internal(String),
    InvalidMediaType,
    Encoded(String),
    Decoding(String),
}

pub trait StatusMapProvider<I: ?Sized, T: EncodedStatusMap> {
    #[allow(async_fn_in_trait)]
    async fn get(&self, id: &I) -> Result<MaybeCached<T::Decoded>, ProviderError>;
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
