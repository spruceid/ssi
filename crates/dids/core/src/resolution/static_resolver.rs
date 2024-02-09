use std::collections::HashMap;

use crate::{DIDBuf, DIDResolver, DID};

use super::{Error, Options, Output};

/// A simple static DID resolver to perform tests.
#[derive(Debug, Default, Clone)]
pub struct StaticDIDResolver {
    map: HashMap<DIDBuf, Output<Vec<u8>>>,
}

impl StaticDIDResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, did: DIDBuf, value: Output<Vec<u8>>) -> Option<Output<Vec<u8>>> {
        self.map.insert(did, value)
    }
}

impl DIDResolver for StaticDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        _options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        match self.map.get(did) {
            Some(data) => Ok(data.clone()),
            None => Err(Error::NotFound),
        }
    }
}
