use ssi_data_integrity_core::suite::standard::TransformationError;
use ssi_di_sd_primitives::{
    canonicalize::create_hmac_id_label_map_function, group::canonicalize_and_group, HmacShaAnyKey,
    IntoHmacError, ShaAny,
};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdNodeObject};
use ssi_rdf::{LexicalInterpretation, LexicalQuad};
use ssi_verification_methods::{multikey::DecodedMultikey, Multikey};
use std::{borrow::Cow, collections::HashMap};

use crate::ecdsa_sd_2023::SignatureOptions;

#[derive(Debug, Clone)]
pub struct TransformedBase {
    pub options: SignatureOptions,
    pub mandatory: Vec<LexicalQuad>,
    pub non_mandatory: Vec<LexicalQuad>,
    pub hmac_key: HmacShaAnyKey,
    pub canonical_configuration: Vec<String>,
}

/// Base Proof Transformation.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#base-proof-transformation-ecdsa-sd-2023>
pub async fn base_proof_transformation<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    canonical_configuration: Vec<String>,
    verification_method: &Multikey,
    transform_options: SignatureOptions,
) -> Result<TransformedBase, TransformationError>
where
    T: JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let decoded_key = verification_method
        .public_key
        .decode()
        .map_err(|_| TransformationError::InvalidKey)?;

    let sha = match decoded_key {
        #[cfg(feature = "secp256r1")]
        DecodedMultikey::P256(_) => ShaAny::Sha256,
        #[cfg(feature = "secp384r1")]
        DecodedMultikey::P384(_) => ShaAny::Sha384,
        _ => return Err(TransformationError::InvalidKey),
    };

    let hmac_key = sha
        .into_key(transform_options.hmac_key)
        .map_err(hmac_error)?;
    let mut hmac = hmac_key.to_hmac();

    let label_map_factory_function = create_hmac_id_label_map_function(&mut hmac);

    let mut group_definitions = HashMap::new();
    group_definitions.insert(
        Mandatory,
        Cow::Borrowed(transform_options.mandatory_pointers.as_slice()),
    );

    let mut canonical = canonicalize_and_group(
        loader,
        label_map_factory_function,
        group_definitions,
        unsecured_document,
    )
    .await
    .map_err(TransformationError::internal)?;

    let mandatory_group = canonical.groups.remove(&Mandatory).unwrap();
    let mandatory = mandatory_group.matching.into_values().collect();
    let non_mandatory = mandatory_group.non_matching.into_values().collect();

    Ok(TransformedBase {
        options: transform_options,
        mandatory,
        non_mandatory,
        hmac_key,
        canonical_configuration,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mandatory;

fn hmac_error(e: IntoHmacError) -> TransformationError {
    match e {
        IntoHmacError::IncompatibleKey => TransformationError::InvalidKey,
        IntoHmacError::RandomGenerationFailed(e) => TransformationError::internal(e),
    }
}
