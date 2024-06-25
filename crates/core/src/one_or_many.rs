use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// One or many.
///
/// Serializes/deserializes into/from either a value, or an array of values.
#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),

    /// An array of values.
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn any<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        match self {
            Self::One(value) => f(value),
            Self::Many(values) => values.iter().any(f),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(values) => values.is_empty(),
        }
    }

    pub fn contains(&self, x: &T) -> bool
    where
        T: PartialEq<T>,
    {
        match self {
            Self::One(value) => x == value,
            Self::Many(values) => values.contains(x),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(t) => std::slice::from_ref(t),
            Self::Many(l) => l.as_slice(),
        }
    }

    pub fn first(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if !values.is_empty() {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn to_single(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if values.len() == 1 {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn to_single_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if values.len() == 1 {
                    Some(&mut values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn into_single(self) -> Option<T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                let mut it = values.into_iter();
                let value = it.next()?;
                if it.next().is_none() {
                    Some(value)
                } else {
                    None
                }
            }
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(t) => vec![t],
            Self::Many(v) => v,
        }
    }
}

// consuming iterator
impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(value) => vec![value].into_iter(),
            Self::Many(values) => values.into_iter(),
        }
    }
}

// non-consuming iterator
impl<'a, T> IntoIterator for &'a OneOrMany<T> {
    type Item = &'a T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            OneOrMany::One(value) => vec![value].into_iter(),
            OneOrMany::Many(values) => values.iter().collect::<Vec<Self::Item>>().into_iter(),
        }
    }
}

impl<'de, T> Deserialize<'de> for OneOrMany<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(Visitor(PhantomData))
    }
}

struct Visitor<T>(PhantomData<T>);

impl<'de, T> serde::de::Visitor<'de> for Visitor<T>
where
    T: Deserialize<'de>,
{
    type Value = OneOrMany<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "one or more values")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::UnitDeserializer::new()).map(OneOrMany::One)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::BoolDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::U8Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::U16Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::U32Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::U64Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::U128Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::I8Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::I16Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::I32Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::I64Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::I128Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::F32Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::F64Deserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::CharDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::BytesDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::BorrowedBytesDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::BytesDeserializer::new(&v)).map(OneOrMany::One)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::StrDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::BorrowedStrDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(serde::de::value::StringDeserializer::new(v)).map(OneOrMany::One)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::deserialize(NoneDeserializer::<T, E>(PhantomData)).map(OneOrMany::One)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        T::deserialize(SomeDeserializer::<T, D>(deserializer, PhantomData)).map(OneOrMany::One)
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(OneOrMany::One)
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        T::deserialize(serde::de::value::EnumAccessDeserializer::new(data)).map(OneOrMany::One)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        T::deserialize(NewtypeStructDeserializer::<T, D>(deserializer, PhantomData))
            .map(OneOrMany::One)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut many = Vec::new();

        while let Some(t) = seq.next_element::<T>()? {
            many.push(t);
        }

        Ok(OneOrMany::Many(many))
    }
}

struct NoneDeserializer<T, E>(PhantomData<(T, E)>);

impl<'de, T, E> serde::de::Deserializer<'de> for NoneDeserializer<T, E>
where
    T: Deserialize<'de>,
    E: serde::de::Error,
{
    type Error = E;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_none()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct SomeDeserializer<T, D>(D, PhantomData<T>);

impl<'de, T, D> serde::de::Deserializer<'de> for SomeDeserializer<T, D>
where
    T: Deserialize<'de>,
    D: serde::de::Deserializer<'de>,
{
    type Error = D::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct NewtypeStructDeserializer<T, D>(D, PhantomData<T>);

impl<'de, T, D> serde::de::Deserializer<'de> for NewtypeStructDeserializer<T, D>
where
    T: Deserialize<'de>,
    D: serde::de::Deserializer<'de>,
{
    type Error = D::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

/// One or many reference(s).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrManyRef<'a, T> {
    One(&'a T),
    Many(&'a [T]),
}

impl<'a, T> OneOrManyRef<'a, T> {
    pub fn from_slice(s: &'a [T]) -> Self {
        match s {
            [t] => Self::One(t),
            _ => Self::Many(s),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Many([]))
    }
}
