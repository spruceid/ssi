use serde::Serialize;

use crate::{Struct, Value};

mod key;
mod non_serializable;
mod structure;

use key::KeySerializer;
pub use structure::to_struct;

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Bool(b) => b.serialize(serializer),
            Self::Integer(i) => i.serialize(serializer),
            Self::String(s) => s.serialize(serializer),
            Self::Bytes(b) => b.serialize(serializer),
            Self::Array(a) => a.serialize(serializer),
            Self::Struct(s) => s.serialize(serializer),
        }
    }
}

pub fn to_value<T: ?Sized + Serialize>(value: &T) -> Result<Value, InvalidValue> {
    value.serialize(ValueSerializer)
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidValue {
    #[error("invalid data")]
    InvalidData,

    #[error("invalid key")]
    InvalidKey,

    #[error("missing key")]
    MissingKey,

    #[error("integer overflow")]
    IntegerOverflow,

    #[error("{0}")]
    Custom(String),
}

impl serde::ser::Error for InvalidValue {
    fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}

pub struct ValueSerializer;

impl serde::Serializer for ValueSerializer {
    type Ok = Value;

    type Error = InvalidValue;

    type SerializeMap = StructSerializer;

    type SerializeSeq = ArraySerializer;

    type SerializeStruct = StructSerializer;

    type SerializeStructVariant = StructSerializer;

    type SerializeTuple = ArraySerializer;

    type SerializeTupleStruct = ArraySerializer;

    type SerializeTupleVariant = ArraySerializer;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Bool(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        match i64::try_from(v) {
            Ok(v) => Ok(Value::Integer(v)),
            Err(_) => Err(InvalidValue::IntegerOverflow),
        }
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        match i64::try_from(v) {
            Ok(v) => Ok(Value::Integer(v)),
            Err(_) => Err(InvalidValue::IntegerOverflow),
        }
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Integer(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        match i64::try_from(v) {
            Ok(v) => Ok(Value::Integer(v)),
            Err(_) => Err(InvalidValue::IntegerOverflow),
        }
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(v.to_owned()))
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(StructSerializer {
            result: Struct::with_capacity(len.unwrap_or_default()),
            key: None,
        })
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(ArraySerializer(Vec::with_capacity(len.unwrap_or_default())))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(StructSerializer {
            result: Struct::with_capacity(len),
            key: None,
        })
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(StructSerializer {
            result: Struct::with_capacity(len),
            key: None,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(ArraySerializer(Vec::with_capacity(len)))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(ArraySerializer(Vec::with_capacity(len)))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(ArraySerializer(Vec::with_capacity(len)))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Struct(Struct::new()))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(variant.to_string()))
    }
}

pub struct ArraySerializer(Vec<Value>);

impl serde::ser::SerializeSeq for ArraySerializer {
    type Ok = Value;

    type Error = InvalidValue;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.0.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.0))
    }
}

impl serde::ser::SerializeTuple for ArraySerializer {
    type Ok = Value;
    type Error = InvalidValue;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.0.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.0))
    }
}

impl serde::ser::SerializeTupleStruct for ArraySerializer {
    type Ok = Value;
    type Error = InvalidValue;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.0.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.0))
    }
}

impl serde::ser::SerializeTupleVariant for ArraySerializer {
    type Ok = Value;
    type Error = InvalidValue;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.0.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.0))
    }
}

pub struct StructSerializer {
    result: Struct,
    key: Option<String>,
}

impl serde::ser::SerializeMap for StructSerializer {
    type Ok = Value;

    type Error = InvalidValue;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.key = Some(key.serialize(KeySerializer)?);
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let value = to_value(value)?;
        let key = self.key.take().ok_or(InvalidValue::MissingKey)?;
        self.result.insert(key, value);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Struct(self.result))
    }
}

impl serde::ser::SerializeStruct for StructSerializer {
    type Ok = Value;

    type Error = InvalidValue;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let value = to_value(value)?;
        self.result.insert(key.to_string(), value);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Struct(self.result))
    }
}

impl serde::ser::SerializeStructVariant for StructSerializer {
    type Ok = Value;
    type Error = InvalidValue;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let value = to_value(value)?;
        self.result.insert(key.to_string(), value);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Struct(self.result))
    }
}
