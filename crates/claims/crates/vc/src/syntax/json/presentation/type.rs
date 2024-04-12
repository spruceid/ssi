use serde::{ser::SerializeSeq, Deserialize, Serialize};
use ssi_json_ld::JsonLdTypes;
use std::{borrow::Cow, marker::PhantomData};

use crate::VERIFIABLE_PRESENTATION_TYPE;

pub trait RequiredPresentationTypeSet {
    const REQUIRED_PRESENTATION_TYPES: &'static [&'static str];
}

impl RequiredPresentationTypeSet for () {
    const REQUIRED_PRESENTATION_TYPES: &'static [&'static str] = &[];
}

#[derive(Debug, Default, Clone)]
pub struct JsonPresentationTypes<T = ()>(Vec<String>, PhantomData<T>);

impl<T> JsonPresentationTypes<T> {
    pub fn additional_types(&self) -> &[String] {
        &self.0
    }

    pub fn to_json_ld_types(&self) -> JsonLdTypes {
        JsonLdTypes::new(&[VERIFIABLE_PRESENTATION_TYPE], Cow::Borrowed(&self.0))
    }
}

impl<T> Serialize for JsonPresentationTypes<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.is_empty() {
            VERIFIABLE_PRESENTATION_TYPE.serialize(serializer)
        } else {
            let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
            seq.serialize_element(VERIFIABLE_PRESENTATION_TYPE)?;
            for t in &self.0 {
                seq.serialize_element(t)?;
            }
            seq.end()
        }
    }
}

impl<'de, T: RequiredPresentationTypeSet> Deserialize<'de> for JsonPresentationTypes<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: RequiredPresentationTypeSet> serde::de::Visitor<'de> for Visitor<T> {
            type Value = JsonPresentationTypes<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "credential types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v == VERIFIABLE_PRESENTATION_TYPE {
                    for &required in T::REQUIRED_PRESENTATION_TYPES {
                        if required != VERIFIABLE_PRESENTATION_TYPE {
                            return Err(E::custom(format!(
                                "expected required `{}` type",
                                required
                            )));
                        }
                    }

                    Ok(JsonPresentationTypes(Vec::new(), PhantomData))
                } else {
                    Err(E::custom(format!(
                        "expected required `{}` type",
                        VERIFIABLE_PRESENTATION_TYPE
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
                    if t == VERIFIABLE_PRESENTATION_TYPE {
                        base_type = true
                    } else {
                        types.push(t)
                    }
                }

                if !base_type {
                    return Err(<A::Error as serde::de::Error>::custom(format!(
                        "expected required `{}` type",
                        VERIFIABLE_PRESENTATION_TYPE
                    )));
                }

                for &required in T::REQUIRED_PRESENTATION_TYPES {
                    if !types.iter().any(|s| s == required) {
                        return Err(<A::Error as serde::de::Error>::custom(format!(
                            "expected required `{required}` type"
                        )));
                    }
                }

                Ok(JsonPresentationTypes(types, PhantomData))
            }
        }

        deserializer.deserialize_any(Visitor(PhantomData))
    }
}
