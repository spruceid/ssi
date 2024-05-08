use crate::{to_value, InvalidValue, Struct};
use serde::Serialize;

use super::{key::KeySerializer, non_serializable::NonSerializable};

pub fn to_struct<T: ?Sized + Serialize>(value: &T) -> Result<Struct, InvalidValue> {
    value.serialize(StructureSerializer)
}

pub struct StructureSerializer;

impl serde::Serializer for StructureSerializer {
    type Ok = Struct;

    type Error = InvalidValue;

    type SerializeMap = ItemSerializer;

    type SerializeSeq = NonSerializable<Struct>;

    type SerializeStruct = ItemSerializer;

    type SerializeStructVariant = ItemSerializer;

    type SerializeTuple = NonSerializable<Struct>;

    type SerializeTupleStruct = NonSerializable<Struct>;

    type SerializeTupleVariant = NonSerializable<Struct>;

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
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
        Ok(ItemSerializer {
            result: Struct::with_capacity(len.unwrap_or_default()),
            key: None,
        })
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(ItemSerializer {
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
        Ok(ItemSerializer {
            result: Struct::with_capacity(len),
            key: None,
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(InvalidValue::InvalidData)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(Struct::new())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(InvalidValue::InvalidData)
    }
}

pub struct ItemSerializer {
    result: Struct,
    key: Option<String>,
}

impl serde::ser::SerializeMap for ItemSerializer {
    type Ok = Struct;

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
        Ok(self.result)
    }
}

impl serde::ser::SerializeStruct for ItemSerializer {
    type Ok = Struct;

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
        Ok(self.result)
    }
}

impl serde::ser::SerializeStructVariant for ItemSerializer {
    type Ok = Struct;
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
        Ok(self.result)
    }
}
