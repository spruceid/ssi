macro_rules! struct_impl {
    ($(#[$docs:meta])*
     $name:ident, $inner:ident, $ty:ident) => {
        $(#[$docs])*
        pub struct $name(pub(crate) $ty);

        inner_impl!($name, $inner, $ty);
        bytes_impl!($name, $ty);
        serdes_impl!($name, $inner);
        raw_impl!($name, $ty);
    };
    ($(#[$docs:meta])*
     $name:ident, $inner:ident, $($field:ident: $ty:ty => $size:expr),+ $(,)?) => {
        $(#[$docs])*
        pub struct $name {
            $(
                pub(crate) $field: $ty,
            )+
        }

        inner_impl!($name, $inner, $($field: $ty => $size,)+);
        bytes_impl!($name, $($field: $ty => $size,)+);
        serdes_impl!($name, $inner);
    };
}

macro_rules! bytes_impl {
    ($name:ident) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = crate::error::Error;

            fn try_from(d: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(d.as_slice())
            }
        }

        impl TryFrom<&Vec<u8>> for $name {
            type Error = crate::error::Error;

            fn try_from(d: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(d.as_slice())
            }
        }

        impl From<[u8; $name::BYTES]> for $name {
            fn from(d: [u8; Self::BYTES]) -> Self {
                Self::try_from(&d[..]).unwrap()
            }
        }

        impl From<&[u8; $name::BYTES]> for $name {
            fn from(d: &[u8; Self::BYTES]) -> Self {
                Self::try_from(&d[..]).unwrap()
            }
        }

        impl From<Box<[u8]>> for $name {
            fn from(d: Box<[u8]>) -> Self {
                let d = d.to_vec();
                Self::try_from(d).unwrap()
            }
        }

        impl From<&Box<[u8]>> for $name {
            fn from(d: &Box<[u8]>) -> Self {
                let d = d.to_vec();
                Self::try_from(d).unwrap()
            }
        }

        impl Into<Box<[u8]>> for $name {
            fn into(self) -> Box<[u8]> {
                self.to_bytes().to_vec().into_boxed_slice()
            }
        }
    };
    ($name:ident, $ty:ident) => {
        impl TryFrom<&[u8]> for $name {
            type Error = crate::error::Error;

            fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
                if d.len() != Self::BYTES {
                    return Err(crate::error::Error::from_msg(
                        1,
                        &format!("Invalid number of bytes: {}", d.len()),
                    ));
                }
                let mut c = std::io::Cursor::new(d);
                let e = $ty::deserialize(&mut c, true)
                    .map_err(|e| crate::error::Error::from_msg(1, &format!("{:?}", e)))?;
                Ok(Self(e))
            }
        }

        bytes_impl!($name);
    };
    ($name:ident, $($field:ident: $ty:ty => $size:expr),+ $(,)?) => {
        impl TryFrom<&[u8]> for $name {
            type Error = crate::error::Error;

            fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
                if d.len() != Self::BYTES {
                    return Err(crate::error::Error::from_msg(
                        1,
                        &format!("Invalid number of bytes: {}", d.len()),
                    ));
                }
                let mut c = std::io::Cursor::new(d);
                let t = Self {
                    $(
                        $field: <$ty>::deserialize(&mut c, true).map_err(|e| crate::error::Error::from_msg(1, &format!("{:?}", e)))?,
                    )+
                };

                Ok(t)
            }
        }

        bytes_impl!($name);
    }
}

macro_rules! display_impl {
    ($name:ident) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let bytes = self.to_bytes();
                write!(f, "{} {{ {} }}", stringify!($name), hex::encode(&bytes[..]))
            }
        }
    };
}

macro_rules! serdes_impl {
    ($name:ident, $inner:ident) => {
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let t = $inner::from(self);
                t.serialize(s)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let inner = $inner::deserialize(d)?;
                $name::try_from(inner).map_err(|e| serde::de::Error::custom(e))
            }
        }
    };
}

macro_rules! raw_impl {
    ($name:ident, $ty:ident) => {
        impl AsRef<$ty> for $name {
            fn as_ref(&self) -> &$ty {
                &self.0
            }
        }

        impl Into<$ty> for $name {
            fn into(self) -> $ty {
                self.0
            }
        }

        impl From<$ty> for $name {
            fn from(d: $ty) -> Self {
                Self(d)
            }
        }
    };
}

macro_rules! inner_impl {
    ($name:ident, $inner:ident, $ty:ident) => {
        #[derive(Serialize, Deserialize)]
        struct $inner(
            #[serde(with = "BigArray")]
            [u8; $name::BYTES]
        );

        impl From<$name> for $inner {
            fn from(d: $name) -> Self {
                Self::from(&d)
            }
        }

        impl From<&$name> for $inner {
            fn from(d: &$name) -> Self {
                let mut c = [0u8; $name::BYTES];
                d.0.serialize(&mut c.as_mut(), true).unwrap();
                Self(c)
            }
        }

        impl TryFrom<&$inner> for $name {
            type Error = String;

            fn try_from(d: &$inner) -> Result<Self, Self::Error> {
                let mut cur = std::io::Cursor::new(d.0);
                let t = $ty::deserialize(&mut cur, true).map_err(|e| e.to_string())?;
                Ok(Self(t))
            }
        }

        impl TryFrom<$inner> for $name {
            type Error = String;

            fn try_from(d: $inner) -> Result<Self, Self::Error> {
                Self::try_from(&d)
            }
        }
    };
    ($name:ident, $inner:ident, $($field:ident: $ty:ty => $size:expr),+ $(,)?) => {
        #[derive(Serialize, Deserialize)]
        struct $inner {
            $(
                #[serde(with = "BigArray")]
                $field: [u8; $size]
            ),+
        }

        impl From<$name> for $inner {
            fn from(d: $name) -> Self {
                Self::from(&d)
            }
        }

        impl From<&$name> for $inner {
            fn from(d: &$name) -> Self {
                Self {
                    $(
                        $field: {
                            let mut c = [0u8; $size];
                            d.$field.serialize(&mut c.as_mut(), true).unwrap();
                            c
                        }
                    ),+
                }
            }
        }

        impl TryFrom<&$inner> for $name {
            type Error = String;

            fn try_from(d: &$inner) -> Result<Self, Self::Error> {
                let t = Self {
                    $(
                        $field: {
                            let mut cur = std::io::Cursor::new(d.$field);
                            <$ty>::deserialize(&mut cur, true).map_err(|e| e.to_string())?
                        },
                    )+
                };
                Ok(t)
            }
        }

        impl TryFrom<$inner> for $name {
            type Error = String;

            fn try_from(d: $inner) -> Result<Self, Self::Error> {
                Self::try_from(&d)
            }
        }
    }
}
