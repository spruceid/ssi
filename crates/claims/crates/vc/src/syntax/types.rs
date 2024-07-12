use educe::Educe;
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use ssi_json_ld::JsonLdTypes;
use std::{borrow::Cow, marker::PhantomData};

pub trait RequiredType {
    const REQUIRED_TYPE: &'static str;
}

pub trait RequiredTypeSet {
    const REQUIRED_TYPES: &'static [&'static str];
}

impl RequiredTypeSet for () {
    const REQUIRED_TYPES: &'static [&'static str] = &[];
}

impl<T: RequiredType> RequiredTypeSet for T {
    const REQUIRED_TYPES: &'static [&'static str] = &[T::REQUIRED_TYPE];
}

pub trait TypeSerializationPolicy {
    const PREFER_ARRAY: bool;
}

/// List of types.
///
/// An unordered list of types that must include `B` (a base type) implementing
/// [`RequiredType`], and more required types given by `T` implementing
/// [`RequiredTypeSet`].
#[derive(Educe)]
#[educe(Debug, Clone)]
pub struct Types<B, T = ()>(Vec<String>, PhantomData<(B, T)>);

impl<B, T: RequiredTypeSet> Default for Types<B, T> {
    fn default() -> Self {
        Self(
            T::REQUIRED_TYPES
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
            PhantomData,
        )
    }
}

impl<B, T> Types<B, T> {
    pub fn additional_types(&self) -> &[String] {
        &self.0
    }
}

impl<B: RequiredType, T> Types<B, T> {
    pub fn to_json_ld_types(&self) -> JsonLdTypes {
        JsonLdTypes::new(&[B::REQUIRED_TYPE], Cow::Borrowed(&self.0))
    }
}

impl<B: RequiredType + TypeSerializationPolicy, T> Serialize for Types<B, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !B::PREFER_ARRAY && self.0.is_empty() {
            B::REQUIRED_TYPE.serialize(serializer)
        } else {
            let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
            seq.serialize_element(B::REQUIRED_TYPE)?;
            for t in &self.0 {
                seq.serialize_element(t)?;
            }
            seq.end()
        }
    }
}

impl<'de, B: RequiredType, T: RequiredTypeSet> Deserialize<'de> for Types<B, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<B, T>(PhantomData<(B, T)>);

        impl<'de, B: RequiredType, T: RequiredTypeSet> serde::de::Visitor<'de> for Visitor<B, T> {
            type Value = Types<B, T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "credential types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v == B::REQUIRED_TYPE {
                    for &required in T::REQUIRED_TYPES {
                        if required != B::REQUIRED_TYPE {
                            return Err(E::custom(format!(
                                "expected required `{}` type",
                                required
                            )));
                        }
                    }

                    Ok(Types(Vec::new(), PhantomData))
                } else {
                    Err(E::custom(format!(
                        "expected required `{}` type",
                        B::REQUIRED_TYPE
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
                    if t == B::REQUIRED_TYPE {
                        base_type = true
                    } else {
                        types.push(t)
                    }
                }

                if !base_type {
                    return Err(<A::Error as serde::de::Error>::custom(format!(
                        "expected required `{}` type",
                        B::REQUIRED_TYPE
                    )));
                }

                for &required in T::REQUIRED_TYPES {
                    if !types.iter().any(|s| s == required) {
                        return Err(<A::Error as serde::de::Error>::custom(format!(
                            "expected required `{required}` type"
                        )));
                    }
                }

                Ok(Types(types, PhantomData))
            }
        }

        deserializer.deserialize_any(Visitor(PhantomData))
    }
}
