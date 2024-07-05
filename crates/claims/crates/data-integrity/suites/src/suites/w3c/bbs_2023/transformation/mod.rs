use super::{Bbs2023InputOptions, HmacKey};
use crate::Bbs2023;
use hmac::Hmac;
use k256::sha2::Sha256;
use rdf_types::{BlankIdBuf, LexicalQuad};
use serde::Serialize;
use ssi_data_integrity_core::{
    suite::standard::{TransformationAlgorithm, TransformationError, TypedTransformationAlgorithm},
    ProofConfigurationRef,
};
use ssi_di_sd_primitives::canonicalize::create_hmac_id_label_map_function;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::{urdna2015::NormalizingSubstitution, LexicalInterpretation};
use std::collections::HashMap;

mod base;
mod derived;

pub struct Bbs2023Transformation;

impl TransformationAlgorithm<Bbs2023> for Bbs2023Transformation {
    type Output = Transformed;
}

impl<T, C> TypedTransformationAlgorithm<Bbs2023, T, C> for Bbs2023Transformation
where
    C: JsonLdLoaderProvider,
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    async fn transform(
        context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
        transformation_options: Option<Bbs2023InputOptions>,
    ) -> Result<Self::Output, TransformationError> {
        let canonical_configuration = proof_configuration
            .expand(context, unsecured_document)
            .await
            .map_err(TransformationError::ProofConfigurationExpansion)?
            .nquads_lines();

        match transformation_options {
            Some(transform_options) => base::base_proof_transformation(
                context.loader(),
                unsecured_document,
                canonical_configuration,
                transform_options,
            )
            .await
            .map(Transformed::Base),
            None => derived::create_verify_data1(
                context.loader(),
                unsecured_document,
                canonical_configuration,
            )
            .await
            .map(Transformed::Derived),
        }
    }
}

/// Creates a label map factory function that uses an HMAC to shuffle canonical
/// blank node identifiers.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#createshuffledidlabelmapfunction>
pub fn create_shuffled_id_label_map_function(
    hmac: &mut Hmac<Sha256>,
) -> impl '_ + FnMut(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf> {
    |canonical_map| {
        let mut map = create_hmac_id_label_map_function(hmac)(canonical_map);

        let mut hmac_ids: Vec<_> = map.values().cloned().collect();
        hmac_ids.sort();

        let mut bnode_keys: Vec<_> = map.keys().cloned().collect();
        bnode_keys.sort();

        for key in bnode_keys {
            let i = hmac_ids.binary_search(&map[&key]).unwrap();
            map.insert(key, BlankIdBuf::new(format!("_:b{}", i)).unwrap());
        }

        map
    }
}

pub enum Transformed {
    Base(TransformedBase),
    Derived(TransformedDerived),
}

impl Transformed {
    pub fn into_base(self) -> Option<TransformedBase> {
        match self {
            Self::Base(b) => Some(b),
            _ => None,
        }
    }
}

/// Result of the Base Proof Transformation algorithm.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
#[derive(Clone)]
pub struct TransformedBase {
    pub options: Bbs2023InputOptions,
    pub mandatory: Vec<LexicalQuad>,
    pub non_mandatory: Vec<LexicalQuad>,
    pub hmac_key: HmacKey,
    pub canonical_configuration: Vec<String>,
}

#[derive(Clone)]
pub struct TransformedDerived {
    pub canonical_configuration: Vec<String>,
    pub quads: Vec<LexicalQuad>,
    pub canonical_id_map: NormalizingSubstitution,
}
