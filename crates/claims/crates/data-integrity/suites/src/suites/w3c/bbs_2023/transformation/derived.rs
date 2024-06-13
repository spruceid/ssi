use super::TransformedDerived;
use rdf_types::Quad;
use serde::Serialize;
use ssi_data_integrity_core::suite::standard::TransformationError;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdNodeObject};
use ssi_rdf::{LdEnvironment, LexicalInterpretation};

/// See: <https://www.w3.org/TR/vc-di-bbs/#createverifydata>
pub async fn create_verify_data1<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    canonical_configuration: Vec<String>,
) -> Result<TransformedDerived, TransformationError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let mut ld = LdEnvironment::default();

    let mut expanded: ExpandedDocument = unsecured_document
        .expand_with(&mut ld, loader)
        .await
        .map_err(TransformationError::json_ld_expansion)?
        .into();
    expanded.canonicalize();

    let quads =
        linked_data::to_lexical_quads_with(&mut ld.vocabulary, &mut ld.interpretation, &expanded)?;

    let canonical_id_map =
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_lexical_quad_ref))
            .into_substitution();

    Ok(TransformedDerived {
        canonical_configuration,
        quads,
        canonical_id_map,
    })
}
