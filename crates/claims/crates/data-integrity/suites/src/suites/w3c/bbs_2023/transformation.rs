use std::{collections::HashMap, hash::Hash};

use getrandom::getrandom;
use hmac::{Hmac, Mac};
use k256::sha2::Sha256;
use rdf_types::{
    BlankIdBuf, LexicalQuad
};
use ssi_data_integrity_core::{
    suite::standard::{TransformationAlgorithm, TransformationError, TypedTransformationAlgorithm},
    ProofConfigurationRef,
};
use ssi_di_sd_primitives::{
    canonicalize::create_hmac_id_label_map_function, group::canonicalize_and_group,
};
use ssi_json_ld::{ContextLoaderEnvironment, Expandable, JsonLdNodeObject};
use ssi_rdf::{urdna2015::NormalizingSubstitution, LexicalInterpretation};

use crate::Bbs2023;

use super::{Bbs2023InputOptions, HmacKey};

pub struct Bbs2023Transformation;

impl TransformationAlgorithm<Bbs2023> for Bbs2023Transformation {
    type Output = Transformed;
}

impl<T, C> TypedTransformationAlgorithm<Bbs2023, T, C> for Bbs2023Transformation
where
    C: ContextLoaderEnvironment,
    T: JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ssi_json_ld::ExpandedDocument>
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
            Some(transform_options) => {
                // Base Proof Transformation algorithm.
                // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
                // Generate a random key
                let mut hmac_key = HmacKey::default();
                getrandom(&mut hmac_key).map_err(TransformationError::internal)?;
                let mut hmac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();

                let mut group_definitions = HashMap::new();
                group_definitions.insert(Mandatory, transform_options.mandatory_pointers.clone());

                let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

                let mut groups = canonicalize_and_group(
                    context.loader(),
                    label_map_factory_function,
                    group_definitions,
                    unsecured_document,
                )
                .await
                .map_err(TransformationError::internal)?
                .groups;

                let mandatory_group = groups.remove(&Mandatory).unwrap();
                let mandatory = mandatory_group.matching.into_values().collect();
                let non_mandatory = mandatory_group.non_matching.into_values().collect();

                Ok(Transformed::Base(TransformedBase {
                    options: transform_options,
                    mandatory,
                    non_mandatory,
                    hmac_key,
                    canonical_configuration,
                }))
            }
            None => {
                // createVerifyData, step 1, 3, 4
                // canonicalize input document into N-Quads.
                // Ok(Transformed::Derived(todo!()))
                todo!()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Mandatory;

/// Creates a label map factory function that uses an HMAC to shuffle canonical
/// blank node identifiers.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#createshuffledidlabelmapfunction>
pub(crate) fn create_shuffled_id_label_map_function(
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

/// Result of the Base Proof Transformation algorithm.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
pub struct TransformedBase {
    pub options: Bbs2023InputOptions,
    pub mandatory: Vec<LexicalQuad>,
    pub non_mandatory: Vec<LexicalQuad>,
    pub hmac_key: HmacKey,
    pub canonical_configuration: Vec<String>,
}

pub struct TransformedDerived {
    pub proof_hash: String,
    pub nquads: Vec<LexicalQuad>,
}
