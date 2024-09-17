use std::collections::{BTreeMap, HashMap};

use rdf_types::{BlankId, BlankIdBuf, LexicalQuad};
use ssi_core::{JsonPointer, JsonPointerBuf};
use ssi_json_ld::syntax::Value;

use crate::{
    canonicalize::relabel_quads,
    skolemize::{compact_to_deskolemized_nquads, SkolemError},
};

#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("dangling JSON pointer")]
    DanglingJsonPointer,

    #[error(transparent)]
    Skolem(#[from] SkolemError),
}

impl From<DanglingJsonPointer> for SelectError {
    fn from(_: DanglingJsonPointer) -> Self {
        Self::DanglingJsonPointer
    }
}

pub async fn select_canonical_nquads(
    loader: &impl ssi_json_ld::Loader,
    urn_scheme: &str,
    pointers: &[JsonPointerBuf],
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    skolemized_compact_document: &ssi_json_ld::syntax::Object,
) -> Result<CanonicalNquadsSelection, SelectError> {
    let selection_document = select_json_ld(pointers, skolemized_compact_document)?;

    let deskolemized_quads = match selection_document.clone() {
        Some(selection_document) => {
            compact_to_deskolemized_nquads(loader, urn_scheme, selection_document).await?
        }
        None => Vec::new(),
    };

    let quads = relabel_quads(label_map, &deskolemized_quads);

    Ok(CanonicalNquadsSelection {
        // selection_document,
        deskolemized_quads,
        quads,
    })
}

pub struct CanonicalNquadsSelection {
    // selection_document: Option<json_ld::syntax::Object>,
    pub deskolemized_quads: Vec<LexicalQuad>,
    pub quads: Vec<LexicalQuad>,
}

/// See: <https://www.w3.org/TR/vc-di-ecdsa/#selectjsonld>
pub fn select_json_ld(
    pointers: &[JsonPointerBuf],
    document: &ssi_json_ld::syntax::Object,
) -> Result<Option<ssi_json_ld::syntax::Object>, DanglingJsonPointer> {
    if pointers.is_empty() {
        return Ok(None);
    }

    let mut selection_document = create_initial_selection_object(document);
    if let Some(context) = document.get("@context").next() {
        selection_document.insert("@context".into(), SparseValue::from_dense(context));
    }

    for pointer in pointers {
        document.select(pointer, &mut selection_document)?;
    }

    Ok(Some(selection_document.into_dense()))
}

fn create_initial_selection(source: &Value) -> SparseValue {
    match source {
        Value::Null => SparseValue::Null,
        Value::Boolean(b) => SparseValue::Boolean(*b),
        Value::Number(n) => SparseValue::Number(n.clone()),
        Value::String(s) => SparseValue::String(s.clone()),
        Value::Array(_) => SparseValue::Array(SparseArray::default()),
        Value::Object(object) => SparseValue::Object(create_initial_selection_object(object)),
    }
}

fn create_initial_selection_object(source: &ssi_json_ld::syntax::Object) -> SparseObject {
    let mut selection = SparseObject::new();

    if let Some(Value::String(id)) = source.get("id").next() {
        if BlankId::new(id).is_err() {
            selection.insert("id".into(), SparseValue::String(id.to_owned()));
        }
    }

    if let Some(type_) = source.get("type").next() {
        selection.insert("type".into(), SparseValue::from_dense(type_));
    }

    selection
}

#[derive(Debug)]
pub enum SparseValue {
    Null,
    Boolean(bool),
    String(ssi_json_ld::syntax::String),
    Number(ssi_json_ld::syntax::NumberBuf),
    Array(SparseArray),
    Object(SparseObject),
}

impl SparseValue {
    pub fn from_dense(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Boolean(b) => Self::Boolean(*b),
            Value::String(s) => Self::String(s.clone()),
            Value::Number(n) => Self::Number(n.clone()),
            Value::Array(a) => Self::Array(SparseArray::from_dense(a)),
            Value::Object(o) => Self::Object(SparseObject::from_dense(o)),
        }
    }

    pub fn into_dense(self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Boolean(b) => Value::Boolean(b),
            Self::Number(n) => Value::Number(n),
            Self::String(s) => Value::String(s),
            Self::Array(a) => Value::Array(a.into_dense()),
            Self::Object(o) => Value::Object(o.into_dense()),
        }
    }
}

#[derive(Debug, Default)]
pub struct SparseArray(BTreeMap<usize, SparseValue>);

impl SparseArray {
    pub fn from_dense(value: &[Value]) -> Self {
        Self(
            value
                .iter()
                .enumerate()
                .map(|(i, item)| (i, SparseValue::from_dense(item)))
                .collect(),
        )
    }

    pub fn get_mut_or_insert_with(
        &mut self,
        i: usize,
        f: impl FnOnce() -> SparseValue,
    ) -> &mut SparseValue {
        self.0.entry(i).or_insert_with(f)
    }

    pub fn into_dense(self) -> Vec<Value> {
        self.0.into_values().map(SparseValue::into_dense).collect()
    }
}

#[derive(Debug, Default)]
pub struct SparseObject(BTreeMap<String, SparseValue>);

impl SparseObject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_dense(value: &ssi_json_ld::syntax::Object) -> Self {
        Self(
            value
                .iter()
                .map(|entry| {
                    (
                        entry.key.as_str().to_owned(),
                        SparseValue::from_dense(&entry.value),
                    )
                })
                .collect(),
        )
    }

    pub fn get_mut_or_insert_with(
        &mut self,
        key: &str,
        f: impl FnOnce() -> SparseValue,
    ) -> &mut SparseValue {
        if !self.0.contains_key(key) {
            self.0.insert(key.to_owned(), f());
        }

        self.0.get_mut(key).unwrap()
    }

    pub fn insert(&mut self, key: String, value: SparseValue) {
        self.0.insert(key, value);
    }

    pub fn into_dense(self) -> ssi_json_ld::syntax::Object {
        self.0
            .into_iter()
            .map(|(key, value)| (key.into(), value.into_dense()))
            .collect()
    }
}

trait Select {
    type Sparse;

    fn select(
        &self,
        pointer: &JsonPointer,
        selection: &mut Self::Sparse,
    ) -> Result<(), DanglingJsonPointer>;
}

impl Select for Value {
    type Sparse = SparseValue;

    fn select(
        &self,
        pointer: &JsonPointer,
        selection: &mut Self::Sparse,
    ) -> Result<(), DanglingJsonPointer> {
        match (self, selection) {
            (Self::Array(a), SparseValue::Array(b)) => a.select(pointer, b),
            (Self::Object(a), SparseValue::Object(b)) => a.select(pointer, b),
            _ => {
                if pointer.is_empty() {
                    Ok(())
                } else {
                    Err(DanglingJsonPointer)
                }
            }
        }
    }
}

impl Select for Vec<Value> {
    type Sparse = SparseArray;

    fn select(
        &self,
        pointer: &JsonPointer,
        selection: &mut Self::Sparse,
    ) -> Result<(), DanglingJsonPointer> {
        match pointer.split_first() {
            Some((token, rest)) => {
                let i = token.as_array_index().ok_or(DanglingJsonPointer)?;
                let a_item = self.get(i).ok_or(DanglingJsonPointer)?;
                let b_item =
                    selection.get_mut_or_insert_with(i, || create_initial_selection(a_item));
                a_item.select(rest, b_item)
            }
            None => {
                *selection = SparseArray::from_dense(self);
                Ok(())
            }
        }
    }
}

impl Select for ssi_json_ld::syntax::Object {
    type Sparse = SparseObject;

    fn select(
        &self,
        pointer: &JsonPointer,
        selection: &mut Self::Sparse,
    ) -> Result<(), DanglingJsonPointer> {
        match pointer.split_first() {
            Some((token, rest)) => {
                let key = token.to_decoded();
                let a_item = self.get(key.as_ref()).next().ok_or(DanglingJsonPointer)?;
                let b_item =
                    selection.get_mut_or_insert_with(&key, || create_initial_selection(a_item));
                a_item.select(rest, b_item)
            }
            None => {
                *selection = SparseObject::from_dense(self);
                Ok(())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("dangling JSON pointer")]
pub struct DanglingJsonPointer;
