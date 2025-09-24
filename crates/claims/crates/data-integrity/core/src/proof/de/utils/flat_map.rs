use std::marker::PhantomData;

use serde::{
    de::{
        self,
        value::{MapDeserializer, SeqDeserializer, StringDeserializer},
    },
    Deserializer,
};

pub struct FlatMapDeserializer<'a, E> {
    entries: &'a mut Vec<Option<(String, serde_json::Value)>>,
    error: PhantomData<E>,
}

impl<'a, E> FlatMapDeserializer<'a, E> {
    pub fn new(entries: &'a mut Vec<Option<(String, serde_json::Value)>>) -> Self {
        Self {
            entries,
            error: PhantomData,
        }
    }
}

macro_rules! unsupported {
    ($($func:ident ($($arg:ty),*))*) => {
        $(
            fn $func<V>(self, $(_: $arg,)* _visitor: V) -> Result<V::Value, Self::Error>
            where
                V: serde::de::Visitor<'de>,
            {
                Err(serde::de::Error::custom("can only flatten structs and maps"))
            }
        )*
    }
}

impl<'a, 'de, E> Deserializer<'de> for FlatMapDeserializer<'a, E>
where
    E: serde::de::Error,
    'de: 'a,
{
    type Error = E;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        for entry in self.entries {
            if let Some((key, value)) = flat_map_take_entry(entry, variants) {
                return visitor.visit_enum(EnumDeserializer::new(key, Some(value)));
            }
        }

        Err(de::Error::custom(format_args!(
            "no variant of enum {} found in flattened data",
            name
        )))
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_map(FlatMapAccess {
            iter: self.entries.iter_mut(),
            pending_content: None,
            _marker: PhantomData,
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_map(FlatStructAccess {
            iter: self.entries.iter_mut(),
            pending_content: None,
            fields,
            _marker: PhantomData,
        })
    }

    fn deserialize_newtype_struct<V>(self, _name: &str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    unsupported! {
        deserialize_option()
        deserialize_bool()
        deserialize_i8()
        deserialize_i16()
        deserialize_i32()
        deserialize_i64()
        deserialize_u8()
        deserialize_u16()
        deserialize_u32()
        deserialize_u64()
        deserialize_f32()
        deserialize_f64()
        deserialize_char()
        deserialize_str()
        deserialize_string()
        deserialize_bytes()
        deserialize_byte_buf()
        deserialize_seq()
        deserialize_tuple(usize)
        deserialize_tuple_struct(&'static str, usize)
        deserialize_identifier()
    }
}

/// Claims one key-value pair from a FlatMapDeserializer's field buffer if the
/// field name matches any of the recognized ones.
fn flat_map_take_entry(
    entry: &mut Option<(String, serde_json::Value)>,
    recognized: &[&str],
) -> Option<(String, serde_json::Value)> {
    // Entries in the FlatMapDeserializer buffer are nulled out as they get
    // claimed for deserialization. We only use an entry if it is still present
    // and if the field is one recognized by the current data structure.
    let is_recognized = match entry {
        None => false,
        Some((k, _v)) => recognized.contains(&k.as_str()),
    };

    if is_recognized {
        entry.take()
    } else {
        None
    }
}

struct FlatMapAccess<'a, E> {
    iter: std::slice::IterMut<'a, Option<(String, serde_json::Value)>>,
    pending_content: Option<serde_json::Value>,
    _marker: PhantomData<E>,
}

impl<'a, 'de, E> de::MapAccess<'de> for FlatMapAccess<'a, E>
where
    E: de::Error,
    'de: 'a,
{
    type Error = E;

    fn next_key_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        for entry in self.iter.by_ref() {
            if let Some((key, content)) = entry.take() {
                self.pending_content = Some(content);
                return seed.deserialize(StringDeserializer::new(key)).map(Some);
            }
        }

        Ok(None)
    }

    fn next_value_seed<T>(&mut self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        match self.pending_content.take() {
            Some(value) => seed.deserialize(value).map_err(de::Error::custom),
            None => Err(de::Error::custom("value is missing")),
        }
    }
}

struct FlatStructAccess<'a, E> {
    iter: std::slice::IterMut<'a, Option<(String, serde_json::Value)>>,
    pending_content: Option<serde_json::Value>,
    fields: &'static [&'static str],
    _marker: PhantomData<E>,
}

impl<'a, 'de, E> de::MapAccess<'de> for FlatStructAccess<'a, E>
where
    E: de::Error,
    'de: 'a,
{
    type Error = E;

    fn next_key_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        for entry in self.iter.by_ref() {
            if let Some((key, content)) = flat_map_take_entry(entry, self.fields) {
                self.pending_content = Some(content);
                return seed.deserialize(StringDeserializer::new(key)).map(Some);
            }
        }

        Ok(None)
    }

    fn next_value_seed<T>(&mut self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        match self.pending_content.take() {
            Some(value) => seed.deserialize(value).map_err(de::Error::custom),
            None => Err(de::Error::custom("value is missing")),
        }
    }
}

pub struct EnumDeserializer<E>
where
    E: de::Error,
{
    variant: String,
    value: Option<serde_json::Value>,
    err: PhantomData<E>,
}

impl<E> EnumDeserializer<E>
where
    E: serde::de::Error,
{
    pub fn new(variant: String, value: Option<serde_json::Value>) -> Self {
        Self {
            variant,
            value,
            err: PhantomData,
        }
    }
}

impl<'de, E> de::EnumAccess<'de> for EnumDeserializer<E>
where
    E: de::Error,
{
    type Error = E;
    type Variant = VariantDeserializer<Self::Error>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), E>
    where
        V: de::DeserializeSeed<'de>,
    {
        let visitor = VariantDeserializer {
            value: self.value,
            err: PhantomData,
        };
        seed.deserialize(StringDeserializer::new(self.variant))
            .map(|v| (v, visitor))
    }
}

pub struct VariantDeserializer<E>
where
    E: de::Error,
{
    value: Option<serde_json::Value>,
    err: PhantomData<E>,
}

impl<'de, E> de::VariantAccess<'de> for VariantDeserializer<E>
where
    E: de::Error,
{
    type Error = E;

    fn unit_variant(self) -> Result<(), E> {
        match self.value {
            Some(value) => de::Deserialize::deserialize(value).map_err(de::Error::custom),
            None => Ok(()),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, E>
    where
        T: de::DeserializeSeed<'de>,
    {
        match self.value {
            Some(value) => seed.deserialize(value).map_err(de::Error::custom),
            None => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"newtype variant",
            )),
        }
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        match self.value {
            Some(serde_json::Value::Array(v)) => {
                de::Deserializer::deserialize_any(SeqDeserializer::new(v.into_iter()), visitor)
                    .map_err(de::Error::custom)
            }
            Some(other) => Err(de::Error::invalid_type(
                content_unexpected(&other),
                &"tuple variant",
            )),
            None => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"tuple variant",
            )),
        }
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        match self.value {
            Some(serde_json::Value::Object(v)) => {
                de::Deserializer::deserialize_any(MapDeserializer::new(v.into_iter()), visitor)
                    .map_err(de::Error::custom)
            }
            Some(serde_json::Value::Array(v)) => {
                de::Deserializer::deserialize_any(SeqDeserializer::new(v.into_iter()), visitor)
                    .map_err(de::Error::custom)
            }
            Some(other) => Err(de::Error::invalid_type(
                content_unexpected(&other),
                &"struct variant",
            )),
            None => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"struct variant",
            )),
        }
    }
}

fn content_unexpected(content: &serde_json::Value) -> de::Unexpected<'_> {
    match content {
        serde_json::Value::Null => de::Unexpected::Unit,
        serde_json::Value::Bool(b) => de::Unexpected::Bool(*b),
        serde_json::Value::Number(_) => de::Unexpected::Other("number"),
        serde_json::Value::String(s) => de::Unexpected::Str(s.as_str()),
        serde_json::Value::Array(_) => de::Unexpected::Seq,
        serde_json::Value::Object(_) => de::Unexpected::Map,
    }
}
