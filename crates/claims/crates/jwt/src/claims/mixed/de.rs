use std::marker::PhantomData;

use serde::de::Visitor;

use crate::{ClaimKind, JWTClaims, RegisteredClaimKind, RegisteredClaims};

struct ClaimsDeserializer<D> {
    inner: D,
    result: RegisteredClaims,
}

impl<'de, D: serde::de::MapAccess<'de>> ClaimsDeserializer<D> {
    fn deserialize_registered_claim(&mut self, kind: RegisteredClaimKind) -> Result<(), D::Error> {
        self.result
            .insert_any(kind.deserialize_value(&mut self.inner)?);
        Ok(())
    }

    fn into_registered_claims(mut self) -> Result<RegisteredClaims, D::Error> {
        while let Some(claim) = self.inner.next_key()? {
            match claim {
                ClaimKind::Registered(r) => self.deserialize_registered_claim(r)?,
                ClaimKind::Unregistered(key) => {
                    return Err(serde::de::Error::custom(format!(
                        "unexpected claim `{}`",
                        key
                    )))
                }
            }
        }

        Ok(self.result)
    }
}

impl<'a, 'de, D: serde::de::MapAccess<'de>> serde::de::MapAccess<'de>
    for &'a mut ClaimsDeserializer<D>
{
    type Error = D::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        loop {
            match self.inner.next_key()? {
                Some(ClaimKind::Registered(r)) => self.deserialize_registered_claim(r)?,
                Some(ClaimKind::Unregistered(key)) => {
                    break Ok(Some(
                        seed.deserialize(serde::de::value::StringDeserializer::new(key))?,
                    ))
                }
                None => break Ok(None),
            }
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        self.inner.next_value_seed(seed)
    }
}

impl<'a, 'de, D: serde::de::MapAccess<'de>> serde::Deserializer<'de>
    for &'a mut ClaimsDeserializer<D>
{
    type Error = D::Error;

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    /// Hint that the `Deserialize` type is expecting a `bool` value.
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `i8` value.
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `i16` value.
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `i32` value.
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `i64` value.
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `i128` value.
    ///
    /// The default behavior unconditionally returns an error.
    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(serde::de::Error::custom("i128 is not supported"))
    }

    /// Hint that the `Deserialize` type is expecting a `u8` value.
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a `u16` value.
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a `u32` value.
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a `u64` value.
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an `u128` value.
    ///
    /// The default behavior unconditionally returns an error.
    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(serde::de::Error::custom("u128 is not supported"))
    }

    /// Hint that the `Deserialize` type is expecting a `f32` value.
    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a `f64` value.
    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a `char` value.
    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a string value and does
    /// not benefit from taking ownership of buffered data owned by the
    /// `Deserializer`.
    ///
    /// If the `Visitor` would benefit from taking ownership of `String` data,
    /// indicate this to the `Deserializer` by using `deserialize_string`
    /// instead.
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a string value and would
    /// benefit from taking ownership of buffered data owned by the
    /// `Deserializer`.
    ///
    /// If the `Visitor` would not benefit from taking ownership of `String`
    /// data, indicate that to the `Deserializer` by using `deserialize_str`
    /// instead.
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a byte array and does not
    /// benefit from taking ownership of buffered data owned by the
    /// `Deserializer`.
    ///
    /// If the `Visitor` would benefit from taking ownership of `Vec<u8>` data,
    /// indicate this to the `Deserializer` by using `deserialize_byte_buf`
    /// instead.
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a byte array and would
    /// benefit from taking ownership of buffered data owned by the
    /// `Deserializer`.
    ///
    /// If the `Visitor` would not benefit from taking ownership of `Vec<u8>`
    /// data, indicate that to the `Deserializer` by using `deserialize_bytes`
    /// instead.
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting an optional value.
    ///
    /// This allows deserializers that encode an optional value as a nullable
    /// value to convert the null value into `None` and a regular value into
    /// `Some(value)`.
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a unit value.
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    /// Hint that the `Deserialize` type is expecting a unit struct with a
    /// particular name.
    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a newtype struct with a
    /// particular name.
    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a sequence of values.
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a sequence of values and
    /// knows how many values there are without looking at the serialized data.
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a tuple struct with a
    /// particular name and number of fields.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting a struct with a particular
    /// name and fields.
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    /// Hint that the `Deserialize` type is expecting an enum value with a
    /// particular name and possible variants.
    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type is expecting the name of a struct
    /// field or the discriminant of an enum variant.
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }

    /// Hint that the `Deserialize` type needs to deserialize a value whose type
    /// doesn't matter because it is ignored.
    ///
    /// Deserializers for non-self-describing formats may not support this mode.
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Map,
            &visitor,
        ))
    }
}

impl<'de, P: serde::Deserialize<'de>> serde::Deserialize<'de> for JWTClaims<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // P::deserialize(PrivateClaimsDeserializer);

        struct Visitor<P>(PhantomData<P>);

        impl<'de, P: serde::Deserialize<'de>> serde::de::Visitor<'de> for Visitor<P> {
            type Value = JWTClaims<P>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "JWT claims")
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut claims_deserializer = ClaimsDeserializer {
                    inner: map,
                    result: RegisteredClaims::new(),
                };

                let private_claims = P::deserialize(&mut claims_deserializer)?;
                let registered_claims = claims_deserializer.into_registered_claims()?;

                Ok(registered_claims.with_private_claims(private_claims))
            }
        }

        deserializer.deserialize_map(Visitor(PhantomData))
    }
}
