use json_syntax::{
    object::{
        Duplicate, Entry, Equivalent, IterMut, Key, RemovedByInsertFront, RemovedByInsertion,
        RemovedEntries, ValuesMut,
    },
    Object, Value,
};
use serde::Serialize;
use std::{borrow::Borrow, hash::Hash, ops::Deref};

/// Non-empty JSON object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NonEmptyObject(Object);

impl NonEmptyObject {
    pub fn try_from_object(object: Object) -> Result<Self, EmptyObject> {
        if object.is_empty() {
            Err(EmptyObject)
        } else {
            Ok(Self(object))
        }
    }

    pub fn as_object(&self) -> &Object {
        &self.0
    }

    pub fn into_object(self) -> Object {
        self.0
    }

    pub fn iter_mut(&mut self) -> IterMut {
        self.0.iter_mut()
    }

    /// Returns an iterator over the values matching the given key.
    ///
    /// Runs in `O(1)` (average).
    pub fn get_mut<Q>(&mut self, key: &Q) -> ValuesMut
    where
        Q: ?Sized + Hash + Equivalent<Key>,
    {
        self.0.get_mut(key)
    }

    /// Returns the unique entry value matching the given key.
    ///
    /// Returns an error if multiple entries match the key.
    ///
    /// Runs in `O(1)` (average).
    pub fn get_unique_mut<Q>(&mut self, key: &Q) -> Result<Option<&mut Value>, Duplicate<&Entry>>
    where
        Q: ?Sized + Hash + Equivalent<Key>,
    {
        self.0.get_unique_mut(key)
    }

    /// Returns the (first) value associated to `key`, or insert a `key`-`value`
    /// entry where `value` is returned by the given function `f`.
    pub fn get_or_insert_with<Q>(&mut self, key: &Q, f: impl FnOnce() -> Value) -> &Value
    where
        Q: ?Sized + Hash + Equivalent<Key> + ToOwned,
        Q::Owned: Into<Key>,
    {
        self.0.get_or_insert_with(key, f)
    }

    /// Returns a mutable reference to the (first) value associated to `key`, or
    /// insert a `key`-`value` entry where `value` is returned by the given
    /// function `f`.
    pub fn get_mut_or_insert_with<Q>(&mut self, key: &Q, f: impl FnOnce() -> Value) -> &mut Value
    where
        Q: ?Sized + Hash + Equivalent<Key> + ToOwned,
        Q::Owned: Into<Key>,
    {
        self.0.get_mut_or_insert_with(key, f)
    }

    /// Push the given key-value pair to the end of the object.
    ///
    /// Returns `true` if the key was not already present in the object,
    /// and `false` otherwise.
    /// Any previous entry matching the key is **not** overridden: duplicates
    /// are preserved, in order.
    ///
    /// Runs in `O(1)`.
    pub fn push(&mut self, key: Key, value: Value) -> bool {
        self.0.push(key, value)
    }

    pub fn push_entry(&mut self, entry: Entry) -> bool {
        self.0.push_entry(entry)
    }

    /// Push the given key-value pair to the top of the object.
    ///
    /// Returns `true` if the key was not already present in the object,
    /// and `false` otherwise.
    /// Any previous entry matching the key is **not** overridden: duplicates
    /// are preserved, in order.
    ///
    /// Runs in `O(n)`.
    pub fn push_front(&mut self, key: Key, value: Value) -> bool {
        self.0.push_front(key, value)
    }

    pub fn push_entry_front(&mut self, entry: Entry) -> bool {
        self.0.push_entry_front(entry)
    }

    /// Inserts the given key-value pair.
    ///
    /// If one or more entries are already matching the given key,
    /// all of them are removed and returned in the resulting iterator.
    /// Otherwise, `None` is returned.
    pub fn insert(&mut self, key: Key, value: Value) -> Option<RemovedByInsertion> {
        self.0.insert(key, value)
    }

    /// Inserts the given key-value pair on top of the object.
    ///
    /// If one or more entries are already matching the given key,
    /// all of them are removed and returned in the resulting iterator.
    pub fn insert_front(&mut self, key: Key, value: Value) -> RemovedByInsertFront {
        self.0.insert_front(key, value)
    }

    /// Sort the entries by key name.
    ///
    /// Entries with the same key are sorted by value.
    pub fn sort(&mut self) {
        self.0.sort()
    }

    /// Tries to remove the entry at the given index.
    ///
    /// Returns an error if this would leave the object empty.
    pub fn try_remove_at(&mut self, index: usize) -> Result<Option<Entry>, EmptyObject> {
        if index == 0 && self.0.len() == 1 {
            Err(EmptyObject)
        } else {
            Ok(self.0.remove_at(index))
        }
    }

    /// Tries to remove all entries associated to the given key.
    ///
    /// Returns an error if this would leave the object empty.
    ///
    /// Runs in `O(n)` time (average).
    pub fn try_remove<'q, Q>(
        &mut self,
        key: &'q Q,
    ) -> Result<RemovedEntries<'_, 'q, Q>, EmptyObject>
    where
        Q: ?Sized + Hash + Equivalent<Key>,
    {
        if self.iter().all(|e| key.equivalent(&e.key)) {
            Err(EmptyObject)
        } else {
            Ok(self.0.remove(key))
        }
    }

    /// Tries to remove the unique entry associated to the given key.
    ///
    /// Returns an error if multiple entries match the key, or if the object
    /// would be left empty.
    ///
    /// Runs in `O(n)` time (average).
    pub fn try_remove_unique<Q>(&mut self, key: &Q) -> Result<Option<Entry>, RemoveUniqueError>
    where
        Q: ?Sized + Hash + Equivalent<Key>,
    {
        if self.iter().all(|e| key.equivalent(&e.key)) {
            Err(RemoveUniqueError::EmptyObject)
        } else {
            self.0.remove_unique(key).map_err(Into::into)
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("empty object")]
pub struct EmptyObject;

#[derive(Debug, thiserror::Error)]
pub enum RemoveUniqueError {
    #[error(transparent)]
    DuplicateEntry(#[from] Duplicate<Entry>),

    #[error("empty object")]
    EmptyObject,
}

impl Deref for NonEmptyObject {
    type Target = Object;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<Object> for NonEmptyObject {
    fn borrow(&self) -> &Object {
        self.as_object()
    }
}

impl AsRef<Object> for NonEmptyObject {
    fn as_ref(&self) -> &Object {
        self.as_object()
    }
}

impl From<NonEmptyObject> for Object {
    fn from(value: NonEmptyObject) -> Self {
        value.into_object()
    }
}

impl TryFrom<Object> for NonEmptyObject {
    type Error = EmptyObject;

    fn try_from(value: Object) -> Result<Self, Self::Error> {
        Self::try_from_object(value)
    }
}

impl<'de> serde::Deserialize<'de> for NonEmptyObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Object::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}
