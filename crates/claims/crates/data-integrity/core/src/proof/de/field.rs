use core::fmt;

use serde::Deserialize;

pub enum TypeField {
    Type,
    Cryptosuite,
    Other(String),
}

pub enum Field {
    Context,
    Created,
    VerificationMethod,
    ProofPurpose,
    Expires,
    Domains,
    Challenge,
    Nonce,
    Other(String),
}

struct TypeFieldVisitor;

impl<'de> serde::de::Visitor<'de> for TypeFieldVisitor {
    type Value = TypeField;

    fn expecting(&self, __formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Formatter::write_str(__formatter, "field identifier")
    }

    fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "type" => Ok(TypeField::Type),
            "cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => Ok(TypeField::Other(__value.to_owned())),
        }
    }

    fn visit_borrowed_str<__E>(self, __value: &'de str) -> Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "type" => Ok(TypeField::Type),
            "cryptosuite" => Ok(TypeField::Cryptosuite),
            _ => Ok(TypeField::Other(__value.to_owned())),
        }
    }
}

impl<'de> Deserialize<'de> for TypeField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(TypeFieldVisitor)
    }
}

struct FieldVisitor;

impl<'de> serde::de::Visitor<'de> for FieldVisitor {
    type Value = Field;

    fn expecting(&self, __formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Formatter::write_str(__formatter, "field identifier")
    }

    fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "@context" => Ok(Field::Context),
            "created" => Ok(Field::Created),
            "verificationMethod" => Ok(Field::VerificationMethod),
            "proofPurpose" => Ok(Field::ProofPurpose),
            "expires" => Ok(Field::Expires),
            "domain" => Ok(Field::Domains),
            "challenge" => Ok(Field::Challenge),
            "nonce" => Ok(Field::Nonce),
            _ => Ok(Field::Other(__value.to_owned())),
        }
    }

    fn visit_borrowed_str<__E>(self, __value: &'de str) -> Result<Self::Value, __E>
    where
        __E: serde::de::Error,
    {
        match __value {
            "@context" => Ok(Field::Context),
            "created" => Ok(Field::Created),
            "verificationMethod" => Ok(Field::VerificationMethod),
            "proofPurpose" => Ok(Field::ProofPurpose),
            "expires" => Ok(Field::Expires),
            "domain" => Ok(Field::Domains),
            "challenge" => Ok(Field::Challenge),
            "nonce" => Ok(Field::Nonce),
            _ => Ok(Field::Other(__value.to_owned())),
        }
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
