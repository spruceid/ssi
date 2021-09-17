/// Implement Serialization methods based on TryFrom
#[macro_export]
macro_rules! serdes_impl {
    ($name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes()[..])
            }
        }

        impl<'a> serde::Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'a>,
            {
                struct DeserializeVisitor;

                impl<'a> serde::de::Visitor<'a> for DeserializeVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("expected byte array")
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<$name, E>
                    where
                        E: serde::de::Error,
                    {
                        $name::try_from(value).map_err(|_| {
                            serde::de::Error::invalid_value(serde::de::Unexpected::Bytes(value), &self)
                        })
                    }
                }

                deserializer.deserialize_bytes(DeserializeVisitor)
            }
        }
    };
}