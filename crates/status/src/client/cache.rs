use std::{
    collections::HashMap,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;

use crate::{EncodedStatusMap, StatusMap};

use super::{MaybeCached, ProviderError, StatusMapProvider, TypedStatusMapProvider};

pub struct Cached<I: ToOwned, T: EncodedStatusMap, R> {
    remote_provider: R,
    map: RwLock<HashMap<I::Owned, CacheEntry<T::Decoded>>>,
    maximum_ttl: Option<Duration>,
}

impl<I: ToOwned, T: EncodedStatusMap, R> Cached<I, T, R> {
    pub fn new(remote_provider: R, maximum_ttl: Option<Duration>) -> Self {
        Self {
            remote_provider,
            map: RwLock::new(HashMap::new()),
            maximum_ttl,
        }
    }
}

impl<I: ToOwned + Eq + Hash, T: EncodedStatusMap, R: TypedStatusMapProvider<I, T>> Cached<I, T, R>
where
    I::Owned: Eq + Hash,
{
    async fn get_entry(&self, id: &I) -> Result<CacheEntry<T::Decoded>, ProviderError> {
        {
            let map = self.map.read();
            if let Some(entry) = map.get(id) {
                if !entry.is_expired(self.maximum_ttl) {
                    return Ok(entry.clone());
                }
            }
        }

        let entry = CacheEntry {
            status_map: Arc::new(self.remote_provider.get_typed(id).await?.into_owned()),
            retrieval_date: Instant::now(),
        };

        let mut map = self.map.write();
        map.insert(id.to_owned(), entry.clone());
        Ok(entry)
    }
}

impl<I: ToOwned + Eq + Hash, T: EncodedStatusMap, R: TypedStatusMapProvider<I, T>>
    StatusMapProvider<I> for Cached<I, T, R>
where
    I::Owned: Eq + Hash,
{
}

impl<I: ToOwned + Eq + Hash, T: EncodedStatusMap, R: TypedStatusMapProvider<I, T>>
    TypedStatusMapProvider<I, T> for Cached<I, T, R>
where
    I::Owned: Eq + Hash,
{
    async fn get_typed(&self, id: &I) -> Result<MaybeCached<T::Decoded>, ProviderError> {
        Ok(MaybeCached::Cached(self.get_entry(id).await?.status_map))
    }
}

pub struct CacheEntry<T> {
    pub status_map: Arc<T>,
    pub retrieval_date: Instant,
}

impl<T: StatusMap> CacheEntry<T> {
    pub fn is_expired(&self, maximum_ttl: Option<Duration>) -> bool {
        let ttl = match (self.status_map.time_to_live(), maximum_ttl) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return false,
        };

        Instant::now().duration_since(self.retrieval_date) >= ttl
    }
}

impl<T> Clone for CacheEntry<T> {
    fn clone(&self) -> Self {
        Self {
            status_map: self.status_map.clone(),
            retrieval_date: self.retrieval_date,
        }
    }
}
