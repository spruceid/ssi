use serde::Serialize;
use ssi_data_integrity_core::{
    suite::standard::{self, TransformationError},
    ProofConfigurationRef,
};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::Multikey;

use crate::EcdsaSd2023;

mod base;
mod derive;

pub use base::TransformedBase;
pub use derive::TransformedDerived;

use super::SignatureOptions;

pub enum TransformationOptions {
    Base(SignatureOptions),
    Derived,
}

pub enum Transformed {
    Base(TransformedBase),
    Derived(TransformedDerived),
}

pub struct TransformationAlgorithm;

impl standard::TransformationAlgorithm<EcdsaSd2023> for TransformationAlgorithm {
    type Output = Transformed;
}

impl<T, C> standard::TypedTransformationAlgorithm<EcdsaSd2023, T, C> for TransformationAlgorithm
where
    C: JsonLdLoaderProvider,
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    async fn transform(
        context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, EcdsaSd2023>,
        verification_method: &Multikey,
        transformation_options: TransformationOptions,
    ) -> Result<Self::Output, standard::TransformationError> {
        let canonical_configuration = proof_configuration
            .expand(context, unsecured_document)
            .await
            .map_err(TransformationError::ProofConfigurationExpansion)?
            .nquads_lines();

        match transformation_options {
            TransformationOptions::Base(signature_options) => base::base_proof_transformation(
                context.loader(),
                unsecured_document,
                canonical_configuration,
                verification_method,
                signature_options,
            )
            .await
            .map(Transformed::Base),
            TransformationOptions::Derived => derive::create_verify_data1(
                context.loader(),
                unsecured_document,
                canonical_configuration,
            )
            .await
            .map(Transformed::Derived),
        }
    }
}
