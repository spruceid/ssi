use std::marker::PhantomData;

use iref::IriBuf;
use serde::de::MapAccess;
use ssi_core::de::DeserializeTyped;
use ssi_verification_methods::ReferenceOrOwned;

pub enum RefOrValue<T> {
    Ref(IriBuf),
    Value(T),
}

impl<T> RefOrValue<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> RefOrValue<U> {
        match self {
            Self::Ref(t) => RefOrValue::Ref(t),
            Self::Value(v) => RefOrValue::Value(f(v)),
        }
    }
}

impl<'de, T: DeserializeTyped<'de, C>, C> DeserializeTyped<'de, C> for RefOrValue<T> {
    fn deserialize_typed<S>(type_: &C, deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::Deserializer<'de>,
    {
        struct Visitor<'a, T, C>(&'a C, PhantomData<T>);

        impl<'a, 'de, T: DeserializeTyped<'de, C>, C> serde::de::Visitor<'de> for Visitor<'a, T, C> {
            type Value = RefOrValue<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "string or map")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_owned())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                IriBuf::new(v).map_err(E::custom).map(RefOrValue::Ref)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                T::deserialize_typed(self.0, serde::de::value::MapAccessDeserializer::new(map))
                    .map(RefOrValue::Value)
            }
        }

        deserializer.deserialize_any(Visitor(type_, PhantomData))
    }
}

impl<M> From<RefOrValue<M>> for ReferenceOrOwned<M> {
    fn from(value: RefOrValue<M>) -> Self {
        match value {
            RefOrValue::Ref(r) => Self::Reference(r),
            RefOrValue::Value(v) => Self::Owned(v),
        }
    }
}
