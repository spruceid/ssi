use serde::de::value::StringDeserializer;

pub struct ReplayMap<M> {
    past: std::vec::IntoIter<(String, serde_json::Value)>,
    past_value: Option<serde_json::Value>,
    future: M,
}

impl<M> ReplayMap<M> {
    pub fn new(past: Vec<(String, serde_json::Value)>, future: M) -> Self {
        Self {
            past: past.into_iter(),
            past_value: None,
            future,
        }
    }
}

impl<'de, M: serde::de::MapAccess<'de>> serde::de::MapAccess<'de> for ReplayMap<M> {
    type Error = M::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        match self.past.next() {
            Some((key, value)) => {
                self.past_value = Some(value);
                seed.deserialize(StringDeserializer::new(key)).map(Some)
            }
            None => self.future.next_key_seed(seed),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        match self.past_value.take() {
            Some(value) => seed.deserialize(value).map_err(serde::de::Error::custom),
            None => self.future.next_value_seed(seed),
        }
    }
}
