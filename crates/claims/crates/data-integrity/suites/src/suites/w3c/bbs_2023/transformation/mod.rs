use super::{Bbs2023BaseInputOptions, Bbs2023InputOptions, HmacKey};
use crate::Bbs2023;
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    interpretation::ReverseTermInterpretation, BlankIdBuf, InterpretationMut, LexicalQuad,
    VocabularyMut,
};
use ssi_data_integrity_core::{
    suite::standard::{TransformationAlgorithm, TransformationError, TypedTransformationAlgorithm},
    ProofConfigurationRef,
};
use ssi_di_sd_primitives::{
    canonicalize::create_hmac_id_label_map_function, group::canonicalize_and_group,
};
use ssi_rdf::LexicalInterpretation;
use ssi_json_ld::{Expandable, JsonLdNodeObject, ContextLoaderEnvironment, ExpandedDocument};
use std::{fmt, hash::Hash};

mod base;
mod derived;

pub struct Bbs2023Transformation;

impl TransformationAlgorithm<Bbs2023> for Bbs2023Transformation {
    type Output = Transformed;
}

impl<T, C> TypedTransformationAlgorithm<Bbs2023, T, C> for Bbs2023Transformation
where
    C: ContextLoaderEnvironment,
    T: JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    async fn transform(
        context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
        transformation_options: Option<Bbs2023InputOptions>,
    ) -> Result<Self::Output, TransformationError> {
        match transformation_options {
            Some(Bbs2023InputOptions::Base(transform_options)) => {
                let canonical_configuration = proof_configuration
                    .expand(context, unsecured_document)
                    .await
                    .map_err(TransformationError::ProofConfigurationExpansion)?
                    .nquads_lines();

                base::base_proof_transformation(
                    context.loader(),
                    unsecured_document,
                    canonical_configuration,
                    transform_options,
                )
                .await
                .map(Transformed::Base)
            }
            Some(Bbs2023InputOptions::Derived(transform_options)) => {
                // https://www.w3.org/TR/vc-di-bbs/#add-derived-proof-bbs-2023

                derived::create_disclosure_data(
                    context.loader(),
                    unsecured_document,
                    &transform_options.proof,
                    &transform_options.selective_pointers,
                    transform_options.presentation_header.as_deref(),
                    &transform_options.feature_option,
                )
                .await;

                todo!()
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
pub struct TransformedBase {
    pub options: Bbs2023BaseInputOptions,
    pub mandatory: Vec<LexicalQuad>,
    pub non_mandatory: Vec<LexicalQuad>,
    pub hmac_key: HmacKey,
    pub canonical_configuration: Vec<String>,
}

pub struct TransformedDerived {
    pub proof_hash: String,
    pub nquads: Vec<LexicalQuad>,
}
