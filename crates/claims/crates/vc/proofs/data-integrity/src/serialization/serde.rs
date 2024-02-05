use std::marker::PhantomData;

use serde::Serialize;
use ssi_claims_core::serde::SerializeClaims;

use crate::{CryptographicSuite, DataIntegrity, Proof};

impl<T: Serialize, S: CryptographicSuite> SerializeClaims for DataIntegrity<T, S>
where
    Proof<S>: Serialize,
{
    fn serialize_with_proof<U>(&self, proof: &Self::Proof, serializer: U) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        macro_rules! error {
            () => {
                Err(<S::Error as serde::ser::Error>::custom(
                    "claims must be serialized as a map",
                ))
            };
        }

        macro_rules! dummy_struct_serializer {
            () => {
                fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_some<T: ?Sized>(self, _value: &T) -> Result<Self::Ok, Self::Error>
                where
                    T: Serialize,
                {
                    error!()
                }

                fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_unit_struct(
                    self,
                    _name: &'static str,
                ) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_unit_variant(
                    self,
                    _name: &'static str,
                    _variant_index: u32,
                    _variant: &'static str,
                ) -> Result<Self::Ok, Self::Error> {
                    error!()
                }

                fn serialize_newtype_struct<T: ?Sized>(
                    self,
                    _name: &'static str,
                    _value: &T,
                ) -> Result<Self::Ok, Self::Error>
                where
                    T: Serialize,
                {
                    error!()
                }

                fn serialize_newtype_variant<T: ?Sized>(
                    self,
                    _name: &'static str,
                    _variant_index: u32,
                    _variant: &'static str,
                    _value: &T,
                ) -> Result<Self::Ok, Self::Error>
                where
                    T: Serialize,
                {
                    error!()
                }

                fn serialize_seq(
                    self,
                    _len: Option<usize>,
                ) -> Result<Self::SerializeSeq, Self::Error> {
                    error!()
                }

                fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
                    error!()
                }

                fn serialize_tuple_struct(
                    self,
                    _name: &'static str,
                    _len: usize,
                ) -> Result<Self::SerializeTupleStruct, Self::Error> {
                    error!()
                }

                fn serialize_tuple_variant(
                    self,
                    _name: &'static str,
                    _variant_index: u32,
                    _variant: &'static str,
                    _len: usize,
                ) -> Result<Self::SerializeTupleVariant, Self::Error> {
                    error!()
                }

                fn serialize_map(
                    self,
                    _len: Option<usize>,
                ) -> Result<Self::SerializeMap, Self::Error> {
                    error!()
                }

                fn serialize_struct_variant(
                    self,
                    _name: &'static str,
                    _variant_index: u32,
                    _variant: &'static str,
                    _len: usize,
                ) -> Result<Self::SerializeStructVariant, Self::Error> {
                    error!()
                }
            };
        }

        struct StructLenSerializer<S>(usize, PhantomData<S>);

        impl<S: serde::Serializer> serde::Serializer for StructLenSerializer<S> {
            type Ok = usize;
            type Error = S::Error;

            type SerializeSeq = serde::ser::Impossible<usize, S::Error>;
            type SerializeTuple = serde::ser::Impossible<usize, S::Error>;
            type SerializeTupleStruct = serde::ser::Impossible<usize, S::Error>;
            type SerializeTupleVariant = serde::ser::Impossible<usize, S::Error>;
            type SerializeMap = serde::ser::Impossible<usize, S::Error>;
            type SerializeStruct = Self;
            type SerializeStructVariant = serde::ser::Impossible<usize, S::Error>;

            dummy_struct_serializer!();

            fn serialize_struct(
                self,
                _name: &'static str,
                _len: usize,
            ) -> Result<Self::SerializeStruct, Self::Error> {
                Ok(self)
            }
        }

        impl<S: serde::Serializer> SerializeStruct for StructLenSerializer<S> {
            type Error = S::Error;
            type Ok = usize;

            fn serialize_field<T: ?Sized>(
                &mut self,
                _key: &'static str,
                _value: &T,
            ) -> Result<(), Self::Error>
            where
                T: Serialize,
            {
                self.0 += 1;
                Ok(())
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Ok(self.0)
            }
        }

        struct FlattenStructSerializer<'a, S: serde::Serializer>(&'a mut S::SerializeStruct);

        impl<'a, S: serde::Serializer> serde::Serializer for FlattenStructSerializer<'a, S> {
            type Ok = ();
            type Error = S::Error;

            type SerializeSeq = serde::ser::Impossible<(), S::Error>;
            type SerializeTuple = serde::ser::Impossible<(), S::Error>;
            type SerializeTupleStruct = serde::ser::Impossible<(), S::Error>;
            type SerializeTupleVariant = serde::ser::Impossible<(), S::Error>;
            type SerializeMap = serde::ser::Impossible<(), S::Error>;
            type SerializeStruct = Self;
            type SerializeStructVariant = serde::ser::Impossible<(), S::Error>;

            dummy_struct_serializer!();

            fn serialize_struct(
                self,
                _name: &'static str,
                _len: usize,
            ) -> Result<Self::SerializeStruct, Self::Error> {
                Ok(self)
            }
        }

        impl<'a, S: serde::Serializer> SerializeStruct for FlattenStructSerializer<'a, S> {
            type Error = S::Error;
            type Ok = ();

            fn serialize_field<T: ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Self::Error>
            where
                T: Serialize,
            {
                self.0.serialize_field(key, value)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Ok(())
            }
        }

        let len = self.serialize(StructLenSerializer(0, PhantomData::<U>))?;
        let mut strct = serializer.serialize_struct("DataIntegrity", len)?;
        self.serialize(FlattenStructSerializer::<U>(&mut strct))?;
        strct.serialize_field("proof", proof)?;
        strct.end()
    }
}
