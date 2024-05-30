use std::marker::PhantomData;

use serde::{de::DeserializeSeed, Deserialize};

pub trait DeserializeTyped<'de, T>: Sized {
    fn deserialize_typed<S>(type_: &T, deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::Deserializer<'de>;
}

impl<'de, T: Deserialize<'de>, C> DeserializeTyped<'de, C> for T {
    fn deserialize_typed<S>(_: &C, deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer)
    }
}

pub struct WithType<'a, T, U>(&'a T, PhantomData<U>);

impl<'a, T, U> WithType<'a, T, U> {
    pub fn new(type_: &'a T) -> Self {
        Self(type_, PhantomData)
    }
}

impl<'a, 'de, T, U: DeserializeTyped<'de, T>> DeserializeSeed<'de> for WithType<'a, T, U> {
    type Value = U;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        U::deserialize_typed(self.0, deserializer)
    }
}

pub trait DeserializeTypedOwned<T>: for<'de> DeserializeTyped<'de, T> {}
impl<T, U> DeserializeTypedOwned<T> for U where U: for<'de> DeserializeTyped<'de, T> {}
