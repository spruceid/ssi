use serde::{Deserialize, Serialize};
use std::{fmt, hash::Hash, ops::Deref, str::FromStr};

/// Value with stable lexical representation.
///
/// Some value (such as date/time) can have multiple lexical representations.
/// When dealing with externally generated data, it is sometime preferable to
/// preserve the lexical representation we are provided with, even if it is not
/// in canonical form.
///
/// This type is a wrapper around a value of type `T` that preserves any
/// eventual lexical representation, found when deserializing (with
/// [`Deserialize::deserialize`]) or parsing (with [`FromStr::from_str`] or
/// [`str::parse`]).
#[derive(Debug, Default, Clone)]
pub struct Lexical<T> {
    /// Logical value.
    value: T,

    /// Lexical value.
    representation: Option<String>,
}

impl<T> Lexical<T> {
    /// Wraps a value without any particular lexical representation.
    ///
    /// The [`fmt::Display`] or [`Serialize`] implementation of `T` will be used
    /// as lexical representation.
    pub fn new(value: T) -> Self {
        Self {
            value,
            representation: None,
        }
    }

    /// Wraps a value with the given lexical representation.
    ///
    /// This representation will be used in the [`fmt::Display`] and
    /// [`Serialize`] implementations.
    ///
    /// It is a logical error to provide a representation that is not a valid
    /// lexical representation of `value`.
    pub fn new_with_representation(value: T, representation: String) -> Self {
        Self {
            value,
            representation: Some(representation),
        }
    }

    /// Wraps a value with the given lexical optional representation.
    ///
    /// If a representation is given, will be used in the [`fmt::Display`] and
    /// [`Serialize`] implementations. Otherwise the `T` implementation of those
    /// traits will be used.
    ///
    /// It is a logical error to provide a representation that is not a valid
    /// lexical representation of `value`.
    pub fn from_parts(value: T, representation: Option<String>) -> Self {
        Self {
            value,
            representation,
        }
    }

    /// Returns a reference to the inner value.
    pub fn as_inner(&self) -> &T {
        &self.value
    }

    /// Clones the inner value.
    pub fn to_value(&self) -> T
    where
        T: Clone,
    {
        self.value.clone()
    }

    /// Returns ownership over the inner value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Breaks `self` into its constituting parts.
    pub fn into_parts(self) -> (T, Option<String>) {
        (self.value, self.representation)
    }
}

impl<T> Deref for Lexical<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> From<T> for Lexical<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: PartialEq> PartialEq for Lexical<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<T: PartialEq> PartialEq<T> for Lexical<T> {
    fn eq(&self, other: &T) -> bool {
        self.value.eq(other)
    }
}

impl<T: Eq> Eq for Lexical<T> {}

impl<T: PartialOrd> PartialOrd for Lexical<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T: PartialOrd> PartialOrd<T> for Lexical<T> {
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(other)
    }
}

impl<T: Ord> Ord for Lexical<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T: Hash> Hash for Lexical<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl<T: FromStr> FromStr for Lexical<T> {
    type Err = T::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse()
            .map(|value| Self::new_with_representation(value, s.to_owned()))
    }
}

impl<T: Serialize> Serialize for Lexical<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.representation {
            Some(r) => r.serialize(serializer),
            None => self.value.serialize(serializer),
        }
    }
}

impl<'de, T> Deserialize<'de> for Lexical<T>
where
    T: FromStr<Err: fmt::Display>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let representation = String::deserialize(deserializer)?;
        representation
            .parse()
            .map_err(serde::de::Error::custom)
            .map(|value| Self::new_with_representation(value, representation))
    }
}

impl<T: fmt::Display> fmt::Display for Lexical<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.representation {
            Some(r) => f.write_str(r),
            None => self.value.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct I32String(i32);

    impl FromStr for I32String {
        type Err = <i32 as FromStr>::Err;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.parse().map(Self)
        }
    }

    impl fmt::Display for I32String {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fmt(f)
        }
    }

    impl Serialize for I32String {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.to_string().serialize(serializer)
        }
    }

    #[test]
    fn preserve_lexical_form() {
        let n: Lexical<I32String> = "00001".parse().unwrap();
        assert_eq!(n.to_string(), "00001");
        assert_eq!(n, I32String(1));
        assert_eq!(
            serde_json::to_value(n).unwrap(),
            serde_json::Value::String("00001".to_owned())
        );

        let m: Lexical<I32String> = serde_json::from_str("\"00001\"").unwrap();
        assert_eq!(m.to_string(), "00001");
        assert_eq!(m, I32String(1));
    }
}
