pub struct ReplayMap<'de, M> {
    past: std::vec::IntoIter<(
        serde::__private::de::Content<'de>,
        serde::__private::de::Content<'de>,
    )>,
    past_value: Option<serde::__private::de::Content<'de>>,
    future: M,
}

impl<'de, M> ReplayMap<'de, M> {
    pub fn new(
        past: Vec<(
            serde::__private::de::Content<'de>,
            serde::__private::de::Content<'de>,
        )>,
        future: M,
    ) -> Self {
        Self {
            past: past.into_iter(),
            past_value: None,
            future,
        }
    }
}

impl<'de, M: serde::de::MapAccess<'de>> serde::de::MapAccess<'de> for ReplayMap<'de, M> {
    type Error = M::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        match self.past.next() {
            Some((key, value)) => {
                self.past_value = Some(value);
                seed.deserialize(serde::__private::de::ContentDeserializer::new(key))
                    .map(Some)
            }
            None => self.future.next_key_seed(seed),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        match self.past_value.take() {
            Some(value) => seed.deserialize(serde::__private::de::ContentDeserializer::new(value)),
            None => self.future.next_value_seed(seed),
        }
    }
}
