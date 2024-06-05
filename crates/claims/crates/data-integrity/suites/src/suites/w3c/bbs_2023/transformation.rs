use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    hash::Hash,
};

use getrandom::getrandom;
use hmac::{Hmac, Mac};
use iref::IriBuf;
use ssi_json_ld::{
    context_processing::{Process, ProcessedOwned}, Compact, ContextLoaderEnvironment, JsonLdProcessor, Profile, RemoteDocument
};
use json_syntax::Value;
use k256::sha2::Sha256;
use linked_data::{IntoQuadsError, LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    generator,
    interpretation::ReverseTermInterpretation,
    vocabulary::{ExtractFromVocabulary, IriVocabularyMut},
    BlankId, BlankIdBuf, Id, Interpretation, InterpretationMut, LexicalQuad, Term, Vocabulary,
    VocabularyMut,
};
use ssi_data_integrity_core::{
    suite::standard::{TransformationAlgorithm, TransformationError, TypedTransformationAlgorithm},
    ProofConfigurationRef,
};
use ssi_json_ld::{JsonLdNodeObject, JsonLdObject, Expandable};
use ssi_rdf::interpretation::WithGenerator;

use crate::Bbs2023;

use super::{FeatureOption, JsonPointer, JsonPointerBuf};

pub struct Bbs2023TransformationOptions {
    feature_options: FeatureOption,
    mandatory_pointers: Vec<JsonPointerBuf>,
}

pub struct Bbs2023Transformation;

impl TransformationAlgorithm<Bbs2023> for Bbs2023Transformation {
    type Output = Transformed;
}

impl<T, C> TypedTransformationAlgorithm<Bbs2023, T, C> for Bbs2023Transformation
where
    C: ContextLoaderEnvironment,
    T: JsonLdNodeObject + Expandable,
    T::Expanded<WithGenerator<ssi_rdf::generator::Blank>, ()>: Into<ssi_json_ld::ExpandedDocument>
{
    async fn transform(
        context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
        transformation_options: Option<Bbs2023TransformationOptions>,
    ) -> Result<Self::Output, TransformationError> {
        let canonical_configuration = proof_configuration
            .expand(context, unsecured_document)
            .await
            .map_err(TransformationError::ProofConfigurationExpansion)?
            .nquads_lines();

        match transformation_options {
            Some(transform_options) => {
                // Base Proof Transformation algorithm.
                // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
                // Generate a random key
                let mut hmac_key = HmacKey::default();
                getrandom(&mut hmac_key).map_err(TransformationError::internal)?;
                let hmac = Hmac::<Sha256>::new_from_slice(&hmac_key);

                let mut group_definitions = HashMap::new();
                group_definitions.insert(Mandatory, transform_options.mandatory_pointers.clone());

                let label_map_factory_function = || todo!();

                let mut groups = canonicalize_and_group(
                    context.loader(),
                    label_map_factory_function,
                    group_definitions,
                    unsecured_document,
                )
                .await?
                .groups;

                let mandatory_group = groups.remove(&Mandatory).unwrap();
                let mandatory = mandatory_group.matching.into_values().collect();
                let non_mandatory = mandatory_group.non_matching.into_values().collect();

                Ok(Transformed::Base(TransformedBase {
                    feature_option: transform_options.feature_options,
                    mandatory_pointers: transform_options.mandatory_pointers,
                    mandatory,
                    non_mandatory,
                    hmac_key,
                    canonical_configuration,
                }))
            }
            None => {
                // createVerifyData, step 1, 3, 4
                // canonicalize input document into N-Quads.
                Ok(Transformed::Derived(todo!()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Mandatory;

fn hmac_id_label_map_function(hmac: &mut Hmac<Sha256>) -> impl '_ + FnMut(&BlankId) -> BlankIdBuf {
    use hmac::Mac;
    let mut map: HashMap<&BlankId, BlankIdBuf> = HashMap::new();
    move |blank_id| {
        hmac.update(blank_id.as_bytes());
        let digest = hmac.finalize_reset().into_bytes();
        let b64_url_digest = format!(
            "u{}",
            base64::encode_config(&digest, base64::URL_SAFE_NO_PAD)
        );
        todo!()
    }
}

/// Canonicalize and group.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#canonicalizeandgroup>
async fn canonicalize_and_group<T, N>(
    loader: &impl ssi_json_ld::Loader,
    label_factory: impl FnMut() -> BlankIdBuf,
    group_definitions: HashMap<N, Vec<JsonPointerBuf>>,
    document: &T,
) -> Result<CanonicalizedAndGrouped<N>, TransformationError>
where
    T: JsonLdObject + Expandable,
    T::Expanded<WithGenerator<ssi_rdf::generator::Blank>, ()>: Into<ssi_json_ld::ExpandedDocument>,
    N: Eq + Hash,
{
    let mut skolemize = Skolemize {
        urn_scheme: String::new(),
        random_string: String::new(),
        count: 0,
    };

    let (skolemized_expanded_document, skolemized_compact_document) =
        skolemize.compact_document(loader, document).await?;

    let deskolemized_quads =
        expanded_to_deskolemized_nquads(&skolemize.urn_scheme, &skolemized_expanded_document)?;

    let (quads, label_map) =
        label_replacement_canonicalize_nquads(label_factory, &deskolemized_quads);

    let mut selection = HashMap::new();
    for (name, pointers) in group_definitions {
        selection.insert(
            name,
            select_canonical_nquads(
                loader,
                &skolemize.urn_scheme,
                pointers,
                &label_map,
                &skolemized_compact_document,
            )
            .await?,
        );
    }

    let mut groups = HashMap::new();

    for (name, selection_result) in selection {
        let mut matching = HashMap::new();
        let mut non_matching = HashMap::new();

        let selected_quads: HashSet<_> = selection_result.quads.into_iter().collect();
        let selected_deskolemized_quads = selection_result.deskolemized_quads;

        for (i, nq) in quads.iter().enumerate() {
            if selected_quads.contains(nq) {
                matching.insert(i, nq.clone());
            } else {
                non_matching.insert(i, nq.clone());
            }
        }

        groups.insert(
            name,
            Group {
                matching,
                non_matching,
                deskolemized_quads: selected_deskolemized_quads,
            },
        );
    }

    Ok(CanonicalizedAndGrouped {
        groups,
        skolemized_expanded_document,
        skolemized_compact_document,
        deskolemized_quads,
        label_map,
        quads,
    })
}

struct CanonicalizedAndGrouped<N> {
    groups: HashMap<N, Group>,
    skolemized_expanded_document: ssi_json_ld::ExpandedDocument,
    skolemized_compact_document: ssi_json_ld::syntax::Object,
    deskolemized_quads: Vec<LexicalQuad>,
    label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    quads: Vec<LexicalQuad>,
}

async fn select_canonical_nquads(
    loader: &impl ssi_json_ld::Loader,
    urn_scheme: &str,
    pointers: Vec<JsonPointerBuf>,
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    skolemized_compact_document: &ssi_json_ld::syntax::Object,
) -> Result<CanonicalNquadsSelection, TransformationError> {
    let selection_document = select_json_ld(pointers, skolemized_compact_document)
        .map_err(TransformationError::internal)?;

    let deskolemized_quads = match selection_document.clone() {
        Some(selection_document) => {
            compact_to_deskolemized_nquads(loader, urn_scheme, selection_document).await?
        }
        None => Vec::new(),
    };

    let quads = relabel_blank_nodes(label_map, &deskolemized_quads);

    Ok(CanonicalNquadsSelection {
        selection_document,
        deskolemized_quads,
        quads,
    })
}

struct CanonicalNquadsSelection {
    selection_document: Option<ssi_json_ld::syntax::Object>,
    deskolemized_quads: Vec<LexicalQuad>,
    quads: Vec<LexicalQuad>,
}

fn relabel_blank_nodes(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    quads: &[LexicalQuad],
) -> Vec<LexicalQuad> {
    todo!()
}

/// See: <https://www.w3.org/TR/vc-di-ecdsa/#selectjsonld>
fn select_json_ld(
    pointers: Vec<JsonPointerBuf>,
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
        document.select(&pointer, &mut selection_document)?;
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

struct JsonPath;

fn select_paths(
    pointer: &JsonPointer,
    mut value: &ssi_json_ld::syntax::Value,
    selection_document: &mut ssi_json_ld::syntax::Object,
) -> Result<(), DanglingJsonPointer> {
    for token in pointer {
        value
            .as_object()
            .and_then(|o| o.get(token.to_str().as_ref()).next())
            .ok_or(DanglingJsonPointer);

        // ...
    }

    todo!()
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
    pub fn from_dense(value: &Vec<Value>) -> Self {
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
        todo!()
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
        todo!()
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
                let key = token.to_str();
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

fn label_replacement_canonicalize_nquads(
    mut label_factory: impl FnMut() -> BlankIdBuf,
    quads: &[LexicalQuad],
) -> (Vec<LexicalQuad>, HashMap<BlankIdBuf, BlankIdBuf>) {
    let mut label_map: HashMap<BlankIdBuf, BlankIdBuf> = HashMap::new();
    let mut relabel = |b: &mut BlankIdBuf| match label_map.get(b.as_blank_id_ref()).cloned() {
        Some(c) => *b = c,
        None => {
            let c = label_factory();
            label_map.insert(b.clone(), c);
        }
    };

    let mut relabel_id = |id: &mut Id| {
        if let Id::Blank(b) = id {
            relabel(b)
        }
    };

    let mut canonical_quads: Vec<LexicalQuad> =
        ssi_rdf::urdna2015::normalize(quads.iter().map(LexicalQuad::as_lexical_quad_ref)).collect();
    for quad in &mut canonical_quads {
        relabel_id(&mut quad.0);
        if let Term::Id(id) = &mut quad.2 {
            relabel_id(id)
        }
        if let Some(g) = &mut quad.3 {
            relabel_id(g)
        }
    }

    (canonical_quads, label_map)
}

fn expanded_to_deskolemized_nquads(
    urn_scheme: &str,
    document: &ssi_json_ld::ExpandedDocument,
) -> Result<Vec<LexicalQuad>, IntoQuadsError> {
    let mut quads = linked_data::to_lexical_quads(generator::Blank::new(), &document)?;

    deskolemize_nquads(urn_scheme, &mut quads);

    Ok(quads)
}

async fn compact_to_deskolemized_nquads(
    loader: &impl ssi_json_ld::Loader,
    urn_scheme: &str,
    document: ssi_json_ld::syntax::Object,
) -> Result<Vec<LexicalQuad>, TransformationError> {
    let mut quads: Vec<LexicalQuad> = RemoteDocument::new(None, None, Value::Object(document))
        .to_rdf(&mut generator::Blank::new(), loader)
        .await
        .map_err(TransformationError::internal)?
        .cloned_quads()
        .map(|quad| quad.map_predicate(|p| p.into_iri().unwrap()))
        .collect();

    deskolemize_nquads(urn_scheme, &mut quads);

    Ok(quads)
}

fn deskolemize_nquads(urn_scheme: &str, quads: &mut [LexicalQuad]) {
    for quad in quads {
        deskolemize_id(urn_scheme, &mut quad.0);
        deskolemize_term(urn_scheme, &mut quad.2);

        if let Some(g) = quad.graph_mut() {
            deskolemize_id(urn_scheme, g);
        }
    }
}

fn deskolemize_id(urn_scheme: &str, id: &mut Id) {
    if let Id::Iri(iri) = id {
        if iri.scheme().as_str() == "urn" {
            let path = iri.path();
            if let Some((prefix, suffix)) = path.split_once(':') {
                if prefix == urn_scheme {
                    let blank_id = BlankIdBuf::from_suffix(suffix).unwrap();
                    *id = Id::Blank(blank_id)
                }
            }
        }
    }
}

fn deskolemize_term(urn_scheme: &str, term: &mut Term) {
    if let Term::Id(id) = term {
        deskolemize_id(urn_scheme, id)
    }
}

struct Skolemize {
    urn_scheme: String,
    random_string: String,
    count: u32,
}

impl rdf_types::Generator for Skolemize {
    fn next(&mut self, vocabulary: &mut ()) -> Id {
        Id::Iri(self.fresh_blank_id())
    }
}

impl Skolemize {
    pub fn fresh_blank_id(&mut self) -> IriBuf {
        let id = IriBuf::new(format!(
            "urn:{}:{}_{}",
            self.urn_scheme, self.random_string, self.count
        ))
        .unwrap();
        self.count += 1;
        id
    }

    pub fn blank_id(&mut self, blank_id: &BlankId) -> IriBuf {
        IriBuf::new(format!("urn:{}:{}", self.urn_scheme, blank_id.suffix())).unwrap()
    }

    /// See: <https://www.w3.org/TR/vc-di-ecdsa/#skolemizecompactjsonld>
    pub async fn compact_document<T>(
        &mut self,
        loader: &impl ssi_json_ld::Loader,
        document: &T,
    ) -> Result<(ssi_json_ld::ExpandedDocument, ssi_json_ld::syntax::Object), TransformationError>
    where
        T: JsonLdObject + Expandable,
        T::Expanded<WithGenerator<ssi_rdf::generator::Blank>, ()>: Into<ssi_json_ld::ExpandedDocument>
    {
        let expanded = document
            .expand(loader)
            .await
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        let skolemized_expanded_document = self.expanded_document(expanded.into());

        let processed_context: ProcessedOwned<IriBuf, BlankIdBuf> = match document.json_ld_context()
        {
            Some(ld_context) => {
                let processed = ld_context
                    .process(&mut (), loader, None)
                    .await
                    .map_err(TransformationError::internal)?
                    .processed;

                ProcessedOwned::new(ld_context.into_owned(), processed)
            }
            None => ProcessedOwned::new(
                ssi_json_ld::syntax::Context::default(),
                ssi_json_ld::Context::default(),
            ),
        };

        let skolemized_compact_document = skolemized_expanded_document
            .compact(processed_context.as_ref(), loader)
            .await
            .map_err(TransformationError::internal)?
            .into_object()
            .ok_or_else(|| TransformationError::internal("expected JSON object"))?;

        Ok((skolemized_expanded_document, skolemized_compact_document))
    }

    /// See: <https://www.w3.org/TR/vc-di-ecdsa/#skolemizeexpandedjsonld>
    pub fn expanded_document(
        &mut self,
        expanded: ssi_json_ld::ExpandedDocument,
    ) -> ssi_json_ld::ExpandedDocument {
        let mut result = expanded.map_ids(
            |i| i,
            |id| match id {
                ssi_json_ld::Id::Valid(id) => match id {
                    Id::Blank(blank_id) => {
                        ssi_json_ld::Id::Valid(Id::Iri(self.blank_id(&blank_id)))
                    }
                    Id::Iri(iri) => {
                        ssi_json_ld::Id::Valid(Id::Iri(iri))
                    }
                },
                ssi_json_ld::Id::Invalid(s) => ssi_json_ld::Id::Invalid(s),
            },
        );

        result.identify_all(self);
        result
    }
}

struct Group {
    pub matching: HashMap<usize, LexicalQuad>,
    pub non_matching: HashMap<usize, LexicalQuad>,
    pub deskolemized_quads: Vec<LexicalQuad>,
}

struct GroupDefinitions {
    mandatory: Vec<JsonPointerBuf>,
}

pub enum Transformed {
    Base(TransformedBase),
    Derived(TransformedDerived),
}

/// Result of the Base Proof Transformation algorithm.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
pub struct TransformedBase {
    pub feature_option: FeatureOption,
    pub mandatory_pointers: Vec<JsonPointerBuf>,
    pub mandatory: Vec<LexicalQuad>,
    pub non_mandatory: Vec<LexicalQuad>,
    pub hmac_key: HmacKey,
    pub canonical_configuration: Vec<String>,
}

pub struct TransformedDerived {
    pub proof_hash: String,
    pub nquads: Vec<LexicalQuad>,
}

type HmacKey = [u8; 32];
