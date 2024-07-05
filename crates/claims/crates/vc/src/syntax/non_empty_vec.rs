use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmptyVec<T: Clone>(Vec<T>);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("expected a non-empty array")]
    Empty,
}

impl<T: Clone> NonEmptyVec<T> {
    pub fn new(t: T) -> Self {
        Self(vec![t])
    }

    pub fn maybe_new(v: Vec<T>) -> Option<Self> {
        Self::try_from(v).ok()
    }

    pub fn push(&mut self, t: T) {
        self.0.push(t)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    pub fn into<T2>(self) -> NonEmptyVec<T2>
    where
        T2: From<T> + Clone,
    {
        self.into_inner()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<T2>>()
            .try_into()
            // Originally was a NonEmptyVec so there is at least one element
            // and therefore we can safely unwrap.
            .unwrap()
    }

    pub fn try_into<T2, E>(self) -> Result<NonEmptyVec<T2>, E>
    where
        T2: TryFrom<T, Error = E> + Clone,
    {
        Ok(self
            .into_inner()
            .into_iter()
            .map(T2::try_from)
            .collect::<Result<Vec<T2>, E>>()?
            .try_into()
            // Originally was a NonEmptyVec so there is at least one element
            // and therefore we can safely unwrap.
            .unwrap())
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            return Err(Error::Empty);
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T: Clone> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T: Clone> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Clone> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}
