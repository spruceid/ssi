use serde::Deserialize;

pub enum TypeField<'de> {
    Type,
    Cryptosuite,
    Other(serde::__private::de::Content<'de>),
}

pub enum Field<'de> {
    Context,
    Created,
    VerificationMethod,
    ProofPurpose,
    Expires,
    Domains,
    Challenge,
    Nonce,
    Other(serde::__private::de::Content<'de>),
}

struct TypeFieldVisitor;

impl<'de> serde::de::Visitor<'de> for TypeFieldVisitor {
    type Value = TypeField<'de>;
    fn expecting(
        &self,
        __formatter: &mut serde::__private::Formatter,
    ) -> serde::__private::fmt::Result {
        serde::__private::Formatter::write_str(__formatter, "field identifier")
    }
    fn visit_bool<__E>(self, __value: bool) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::Bool(
            __value,
        )))
    }
    fn visit_i8<__E>(self, __value: i8) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::I8(__value)))
    }
    fn visit_i16<__E>(self, __value: i16) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::I16(
            __value,
        )))
    }
    fn visit_i32<__E>(self, __value: i32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::I32(
            __value,
        )))
    }
    fn visit_i64<__E>(self, __value: i64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::I64(
            __value,
        )))
    }
    fn visit_u8<__E>(self, __value: u8) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::U8(__value)))
    }
    fn visit_u16<__E>(self, __value: u16) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::U16(
            __value,
        )))
    }
    fn visit_u32<__E>(self, __value: u32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::U32(
            __value,
        )))
    }
    fn visit_u64<__E>(self, __value: u64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::U64(
            __value,
        )))
    }
    fn visit_f32<__E>(self, __value: f32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::F32(
            __value,
        )))
    }
    fn visit_f64<__E>(self, __value: f64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::F64(
            __value,
        )))
    }
    fn visit_char<__E>(self, __value: char) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::Char(
            __value,
        )))
    }
    fn visit_unit<__E>(self) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(TypeField::Other(serde::__private::de::Content::Unit))
    }
    fn visit_str<__E>(self, __value: &str) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "type" => Ok(TypeField::Type),
            "cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => {
                let __value = serde::__private::de::Content::String(
                    serde::__private::ToString::to_string(__value),
                );
                serde::__private::Ok(TypeField::Other(__value))
            }
        }
    }
    fn visit_bytes<__E>(self, __value: &[u8]) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            b"type" => Ok(TypeField::Type),
            b"cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => {
                let __value = serde::__private::de::Content::ByteBuf(__value.to_vec());
                serde::__private::Ok(TypeField::Other(__value))
            }
        }
    }
    fn visit_borrowed_str<__E>(
        self,
        __value: &'de str,
    ) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "type" => Ok(TypeField::Type),
            "cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => {
                let __value = serde::__private::de::Content::Str(__value);
                serde::__private::Ok(TypeField::Other(__value))
            }
        }
    }
    fn visit_borrowed_bytes<__E>(
        self,
        __value: &'de [u8],
    ) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            b"type" => Ok(TypeField::Type),
            b"cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => {
                let __value = serde::__private::de::Content::Bytes(__value);
                serde::__private::Ok(TypeField::Other(__value))
            }
        }
    }
}

impl<'de> Deserialize<'de> for TypeField<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(TypeFieldVisitor)
    }
}

struct FieldVisitor;

impl<'de> serde::de::Visitor<'de> for FieldVisitor {
    type Value = Field<'de>;
    fn expecting(
        &self,
        __formatter: &mut serde::__private::Formatter,
    ) -> serde::__private::fmt::Result {
        serde::__private::Formatter::write_str(__formatter, "field identifier")
    }
    fn visit_bool<__E>(self, __value: bool) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::Bool(__value)))
    }
    fn visit_i8<__E>(self, __value: i8) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::I8(__value)))
    }
    fn visit_i16<__E>(self, __value: i16) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::I16(__value)))
    }
    fn visit_i32<__E>(self, __value: i32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::I32(__value)))
    }
    fn visit_i64<__E>(self, __value: i64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::I64(__value)))
    }
    fn visit_u8<__E>(self, __value: u8) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::U8(__value)))
    }
    fn visit_u16<__E>(self, __value: u16) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::U16(__value)))
    }
    fn visit_u32<__E>(self, __value: u32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::U32(__value)))
    }
    fn visit_u64<__E>(self, __value: u64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::U64(__value)))
    }
    fn visit_f32<__E>(self, __value: f32) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::F32(__value)))
    }
    fn visit_f64<__E>(self, __value: f64) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::F64(__value)))
    }
    fn visit_char<__E>(self, __value: char) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::Char(__value)))
    }
    fn visit_unit<__E>(self) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        serde::__private::Ok(Field::Other(serde::__private::de::Content::Unit))
    }
    fn visit_str<__E>(self, __value: &str) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "@context" => Ok(Field::Context),
            "created" => Ok(Field::Created),
            "verificationMethod" => Ok(Field::VerificationMethod),
            "proofPurpose" => Ok(Field::ProofPurpose),
            "expires" => Ok(Field::Expires),
            "domains" => Ok(Field::Domains),
            "challenge" => Ok(Field::Challenge),
            "nonce" => Ok(Field::Nonce),
            _ => {
                let __value = serde::__private::de::Content::String(
                    serde::__private::ToString::to_string(__value),
                );
                serde::__private::Ok(Field::Other(__value))
            }
        }
    }
    fn visit_bytes<__E>(self, __value: &[u8]) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            b"@context" => Ok(Field::Context),
            b"created" => Ok(Field::Created),
            b"verificationMethod" => Ok(Field::VerificationMethod),
            b"proofPurpose" => Ok(Field::ProofPurpose),
            b"expires" => Ok(Field::Expires),
            b"domains" => Ok(Field::Domains),
            b"challenge" => Ok(Field::Challenge),
            b"nonce" => Ok(Field::Nonce),
            _ => {
                let __value = serde::__private::de::Content::ByteBuf(__value.to_vec());
                serde::__private::Ok(Field::Other(__value))
            }
        }
    }
    fn visit_borrowed_str<__E>(
        self,
        __value: &'de str,
    ) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "@context" => Ok(Field::Context),
            "created" => Ok(Field::Created),
            "verificationMethod" => Ok(Field::VerificationMethod),
            "proofPurpose" => Ok(Field::ProofPurpose),
            "expires" => Ok(Field::Expires),
            "domains" => Ok(Field::Domains),
            "challenge" => Ok(Field::Challenge),
            "nonce" => Ok(Field::Nonce),
            _ => {
                let __value = serde::__private::de::Content::Str(__value);
                serde::__private::Ok(Field::Other(__value))
            }
        }
    }
    fn visit_borrowed_bytes<__E>(
        self,
        __value: &'de [u8],
    ) -> serde::__private::Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            b"@context" => Ok(Field::Context),
            b"created" => Ok(Field::Created),
            b"verificationMethod" => Ok(Field::VerificationMethod),
            b"proofPurpose" => Ok(Field::ProofPurpose),
            b"expires" => Ok(Field::Expires),
            b"domains" => Ok(Field::Domains),
            b"challenge" => Ok(Field::Challenge),
            b"nonce" => Ok(Field::Nonce),
            _ => {
                let __value = serde::__private::de::Content::Bytes(__value);
                serde::__private::Ok(Field::Other(__value))
            }
        }
    }
}

impl<'de> Deserialize<'de> for Field<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
