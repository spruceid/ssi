use iref::IriBuf;
use linked_data::IntoQuadsError;
use rdf_types::{generator, BlankId, BlankIdBuf, Id, LexicalQuad, Term};
use ssi_json_ld::{
    context_processing::{Process, ProcessedOwned},
    syntax::Value,
    Compact, ExpandedDocument, JsonLdProcessor, RemoteDocument,
};
use ssi_json_ld::{Expandable, JsonLdObject};
use ssi_rdf::LexicalInterpretation;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum SkolemError {
    #[error("RDF serialization failed: {0}")]
    ToRdf(String),

    #[error("JSON-LD expansion failed: {0}")]
    JsonLdExpansion(String),

    #[error("JSON-LD context processing failed: {0}")]
    ContextProcessing(String),

    #[error("JSON-LD compaction failed: {0}")]
    Compaction(String),

    #[error("expected JSON object")]
    ExpectedJsonObject,
}

impl SkolemError {
    pub fn to_rdf(e: impl ToString) -> Self {
        Self::ToRdf(e.to_string())
    }

    pub fn json_ld_expansion(e: impl ToString) -> Self {
        Self::JsonLdExpansion(e.to_string())
    }

    pub fn context_processing(e: impl ToString) -> Self {
        Self::ContextProcessing(e.to_string())
    }

    pub fn compaction(e: impl ToString) -> Self {
        Self::Compaction(e.to_string())
    }
}

pub fn expanded_to_deskolemized_nquads(
    urn_scheme: &str,
    document: &ssi_json_ld::ExpandedDocument,
) -> Result<Vec<LexicalQuad>, IntoQuadsError> {
    let mut quads = linked_data::to_lexical_quads(generator::Blank::new(), &document)?;

    deskolemize_nquads(urn_scheme, &mut quads);

    Ok(quads)
}

pub async fn compact_to_deskolemized_nquads(
    loader: &impl ssi_json_ld::Loader,
    urn_scheme: &str,
    document: ssi_json_ld::syntax::Object,
) -> Result<Vec<LexicalQuad>, SkolemError> {
    let mut generator = generator::Blank::new();
    let mut quads: Vec<LexicalQuad> = RemoteDocument::new(None, None, Value::Object(document))
        .to_rdf(&mut generator, loader)
        .await
        .map_err(SkolemError::to_rdf)?
        .cloned_quads()
        .map(|quad| quad.map_predicate(|p| p.into_iri().unwrap()))
        .collect();

    deskolemize_nquads(urn_scheme, &mut quads);

    Ok(quads)
}

pub fn deskolemize_nquads(urn_scheme: &str, quads: &mut [LexicalQuad]) {
    for quad in quads {
        deskolemize_id(urn_scheme, &mut quad.0);
        deskolemize_term(urn_scheme, &mut quad.2);

        if let Some(g) = quad.graph_mut() {
            deskolemize_id(urn_scheme, g);
        }
    }
}

pub fn deskolemize_id(urn_scheme: &str, id: &mut Id) {
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

pub fn deskolemize_term(urn_scheme: &str, term: &mut Term) {
    if let Term::Id(id) = term {
        deskolemize_id(urn_scheme, id)
    }
}

pub struct Skolemize {
    pub urn_scheme: String,
    pub random_string: String,
    pub count: u32,
}

impl Default for Skolemize {
    fn default() -> Self {
        Self {
            urn_scheme: "bnid".to_owned(),
            random_string: Uuid::new_v4().to_string(),
            count: 0,
        }
    }
}

impl rdf_types::Generator for Skolemize {
    fn next(&mut self, _vocabulary: &mut ()) -> Id {
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
    ) -> Result<(ssi_json_ld::ExpandedDocument, ssi_json_ld::syntax::Object), SkolemError>
    where
        T: JsonLdObject + Expandable,
        T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
    {
        let mut expanded = document
            .expand(loader)
            .await
            .map_err(SkolemError::json_ld_expansion)?
            .into();
        expanded.canonicalize();

        let skolemized_expanded_document = self.expanded_document(expanded);

        let processed_context: ProcessedOwned<IriBuf, BlankIdBuf> = match document.json_ld_context()
        {
            Some(ld_context) => {
                let processed = ld_context
                    .process(&mut (), loader, None)
                    .await
                    .map_err(SkolemError::context_processing)?
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
            .map_err(SkolemError::compaction)?
            .into_object()
            .ok_or(SkolemError::ExpectedJsonObject)?;

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
                    Id::Blank(b) => ssi_json_ld::Id::Valid(Id::Iri(self.blank_id(&b))),
                    Id::Iri(i) => ssi_json_ld::Id::Valid(Id::Iri(i)),
                },
                ssi_json_ld::Id::Invalid(s) => ssi_json_ld::Id::Invalid(s),
            },
        );

        result.identify_all(self);
        result
    }
}
