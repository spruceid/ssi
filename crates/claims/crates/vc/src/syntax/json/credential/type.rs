use serde::{ser::SerializeSeq, Deserialize, Serialize};
use ssi_json_ld::JsonLdTypes;
use std::{borrow::Cow, marker::PhantomData};

use crate::VERIFIABLE_CREDENTIAL_TYPE;

pub trait RequiredCredentialTypeSet {
    const REQUIRED_CREDENTIAL_TYPES: &'static [&'static str];
}

impl RequiredCredentialTypeSet for () {
    const REQUIRED_CREDENTIAL_TYPES: &'static [&'static str] = &[];
}

pub trait RequiredCredentialType {
    const REQUIRED_CREDENTIAL_TYPE: &'static str;
}

impl<T: RequiredCredentialType> RequiredCredentialTypeSet for T {
    const REQUIRED_CREDENTIAL_TYPES: &'static [&'static str] = &[T::REQUIRED_CREDENTIAL_TYPE];
}

#[derive(Debug, Clone)]
pub struct JsonCredentialTypes<T = ()>(Vec<String>, PhantomData<T>);

impl<T: RequiredCredentialTypeSet> Default for JsonCredentialTypes<T> {
    fn default() -> Self {
        Self(
            T::REQUIRED_CREDENTIAL_TYPES
                .iter()
                .filter_map(|&i| {
                    if i == VERIFIABLE_CREDENTIAL_TYPE {
                        None
                    } else {
                        Some(i.to_owned())
                    }
                })
                .collect(),
            PhantomData,
        )
    }
}

impl<T> JsonCredentialTypes<T> {
    pub fn additional_types(&self) -> &[String] {
        &self.0
    }

    pub fn to_json_ld_types(&self) -> JsonLdTypes {
        JsonLdTypes::new(&[VERIFIABLE_CREDENTIAL_TYPE], Cow::Borrowed(&self.0))
    }
}

impl<T> Serialize for JsonCredentialTypes<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
        seq.serialize_element(VERIFIABLE_CREDENTIAL_TYPE)?;
        for t in &self.0 {
            seq.serialize_element(t)?;
        }
        seq.end()
    }
}

impl<'de, T: RequiredCredentialTypeSet> Deserialize<'de> for JsonCredentialTypes<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: RequiredCredentialTypeSet> serde::de::Visitor<'de> for Visitor<T> {
            type Value = JsonCredentialTypes<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "credential types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v == VERIFIABLE_CREDENTIAL_TYPE {
                    for &required in T::REQUIRED_CREDENTIAL_TYPES {
                        if required != VERIFIABLE_CREDENTIAL_TYPE {
                            return Err(E::custom(format!(
                                "expected required `{}` type",
                                required
                            )));
                        }
                    }

                    Ok(JsonCredentialTypes(Vec::new(), PhantomData))
                } else {
                    Err(E::custom(format!(
                        "expected required `{}` type",
                        VERIFIABLE_CREDENTIAL_TYPE
                    )))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut base_type = false;
                let mut types = Vec::new();

                while let Some(t) = seq.next_element()? {
                    if t == VERIFIABLE_CREDENTIAL_TYPE {
                        base_type = true
                    } else {
                        types.push(t)
                    }
                }

                if !base_type {
                    return Err(<A::Error as serde::de::Error>::custom(format!(
                        "expected required `{}` type",
                        VERIFIABLE_CREDENTIAL_TYPE
                    )));
                }

                for &required in T::REQUIRED_CREDENTIAL_TYPES {
                    if !types.iter().any(|s| s == required) {
                        return Err(<A::Error as serde::de::Error>::custom(format!(
                            "expected required `{required}` type"
                        )));
                    }
                }

                Ok(JsonCredentialTypes(types, PhantomData))
            }
        }

        deserializer.deserialize_any(Visitor(PhantomData))
    }
}
