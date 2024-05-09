use serde::{Deserialize, Serialize};

/// One or many.
///
/// Serializes/deserializes into/from either a value, or an array of values.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),

    /// An array of values.
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn any<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        match self {
            Self::One(value) => f(value),
            Self::Many(values) => values.iter().any(f),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(values) => values.is_empty(),
        }
    }

    pub fn contains(&self, x: &T) -> bool
    where
        T: PartialEq<T>,
    {
        match self {
            Self::One(value) => x == value,
            Self::Many(values) => values.contains(x),
        }
    }

    pub fn first(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if !values.is_empty() {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn to_single(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if values.len() == 1 {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn to_single_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                if values.len() == 1 {
                    Some(&mut values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn into_single(self) -> Option<T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                let mut it = values.into_iter();
                let value = it.next()?;
                if it.next().is_none() {
                    Some(value)
                } else {
                    None
                }
            }
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(t) => vec![t],
            Self::Many(v) => v,
        }
    }
}

// consuming iterator
impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(value) => vec![value].into_iter(),
            Self::Many(values) => values.into_iter(),
        }
    }
}

// non-consuming iterator
impl<'a, T> IntoIterator for &'a OneOrMany<T> {
    type Item = &'a T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            OneOrMany::One(value) => vec![value].into_iter(),
            OneOrMany::Many(values) => values.iter().collect::<Vec<Self::Item>>().into_iter(),
        }
    }
}

/// One or many reference(s).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrManyRef<'a, T> {
    One(&'a T),
    Many(&'a [T]),
}

impl<'a, T> OneOrManyRef<'a, T> {
    pub fn from_slice(s: &'a [T]) -> Self {
        match s {
            [t] => Self::One(t),
            _ => Self::Many(s),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Many([]))
    }
}
