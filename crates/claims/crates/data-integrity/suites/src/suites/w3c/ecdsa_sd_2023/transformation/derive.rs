// use ssi_data_integrity_core::suite::standard::TransformationError;

use rdf_types::Quad;
use serde::Serialize;
use ssi_data_integrity_core::suite::standard::TransformationError;
use ssi_json_ld::{
    syntax::Value, Expandable, ExpandedDocument, JsonLdNodeObject, JsonLdProcessor, RemoteDocument,
};
use ssi_rdf::{urdna2015::NormalizingSubstitution, LexicalInterpretation, LexicalQuad};

pub struct TransformedDerived {
    pub canonical_configuration: Vec<String>,
    pub quads: Vec<LexicalQuad>,
    pub canonical_id_map: NormalizingSubstitution,
}

pub async fn create_verify_data1<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    canonical_configuration: Vec<String>,
) -> Result<TransformedDerived, TransformationError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    // Serialize with `to_rdf`, matching the issuer-side `canonicalize_and_group`.
    // `to_lexical_quads` rewrites context-coerced literal datatypes to the
    // canonical `http://…`, which wouldn't match the as-signed quads.
    let value: Value = json_syntax::to_value(unsecured_document)
        .map_err(TransformationError::json_ld_expansion)?;

    let mut generator = rdf_types::generator::Blank::new();
    let quads: Vec<LexicalQuad> = RemoteDocument::new(None, None, value)
        .to_rdf(&mut generator, loader)
        .await
        .map_err(TransformationError::json_ld_expansion)?
        .cloned_quads()
        .map(|quad| quad.map_predicate(|p| p.into_iri().unwrap()))
        .collect();

    let canonical_id_map =
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_lexical_quad_ref))
            .into_substitution();

    Ok(TransformedDerived {
        canonical_configuration,
        quads,
        canonical_id_map,
    })
}
