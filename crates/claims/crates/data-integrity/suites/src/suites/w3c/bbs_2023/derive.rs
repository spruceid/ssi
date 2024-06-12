use std::{borrow::Cow, collections::HashMap, hash::Hash};

use hmac::{digest::KeyInit, Hmac};
use k256::sha2::Sha256;
use rdf_types::{
    BlankIdBuf, Quad
};
use serde::{Deserialize, Serialize};
use ssi_bbs::{proof_gen, ProofGenFailed};
use ssi_data_integrity_core::{DataIntegrity, Proof};
use ssi_di_sd_primitives::{
    group::{canonicalize_and_group, GroupError},
    select::{select_json_ld, DanglingJsonPointer},
    JsonPointerBuf,
};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::{
    multikey::{self, DecodedMultikey},
    Multikey,
};

use crate::{bbs_2023::transformation::create_shuffled_id_label_map_function, Bbs2023};

use super::{
    Bbs2023Signature, Bbs2023SignatureDescription, InvalidBbs2023Signature,
    UnsupportedBbs2023Signature,
};

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("JSON serialization failed: {0}")]
    JsonSerialization(#[from] json_syntax::SerializeError),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid base signature")]
    InvalidBaseSignature,

    #[error(transparent)]
    Group(#[from] GroupError),

    #[error("proof generation failed")]
    ProofGen,

    #[error("dangling JSON pointer")]
    DanglingJsonPointer,

    #[error("unsupported feature")]
    UnsupportedFeature,
}

impl From<InvalidBbs2023Signature> for DeriveError {
    fn from(_value: InvalidBbs2023Signature) -> Self {
        Self::InvalidBaseSignature
    }
}

impl From<multikey::InvalidPublicKey> for DeriveError {
    fn from(_value: multikey::InvalidPublicKey) -> Self {
        Self::InvalidPublicKey
    }
}

impl From<ProofGenFailed> for DeriveError {
    fn from(_value: ProofGenFailed) -> Self {
        Self::ProofGen
    }
}

impl From<DanglingJsonPointer> for DeriveError {
    fn from(_value: DanglingJsonPointer) -> Self {
        Self::DanglingJsonPointer
    }
}

impl From<UnsupportedBbs2023Signature> for DeriveError {
    fn from(_value: UnsupportedBbs2023Signature) -> Self {
        Self::UnsupportedFeature
    }
}

pub struct DeriveOptions {
    pub base_proof: Proof<Bbs2023>,
    pub selective_pointers: Vec<JsonPointerBuf>,
    pub presentation_header: Option<Vec<u8>>,
    pub feature_option: DerivedFeatureOption,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "featureOption")]
pub enum DerivedFeatureOption {
    Baseline,
    AnonymousHolderBinding {
        holder_secret: String,
        prover_blind: String,
    },
    PseudonymIssuerPid {
        verifier_id: String,
    },
    PseudonymHiddenPid {
        pid: String,
        prover_blind: String,
        verifier_id: String,
    },
}

/// See: <https://www.w3.org/TR/vc-di-bbs/#add-derived-proof-bbs-2023>
pub async fn add_derived_proof<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    verification_method: &Multikey,
    options: DeriveOptions,
) -> Result<DataIntegrity<json_syntax::Object, Bbs2023>, DeriveError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let data = create_disclosure_data(
        loader,
        unsecured_document,
        verification_method,
        &options.base_proof.signature,
        options.selective_pointers,
        options.presentation_header.as_deref(),
        &options.feature_option,
    )
    .await?;

    let mut new_proof = options.base_proof;
    new_proof.signature = Bbs2023Signature::encode_derived(
        &data.bbs_proof,
        &data.label_map,
        &data.mandatory_indexes,
        &data.selective_indexes,
        options.presentation_header.as_deref(),
        &options.feature_option,
    )?;

    Ok(DataIntegrity::new(data.reveal_document, new_proof.into()))
}

struct DisclosureData {
    pub bbs_proof: Vec<u8>,
    pub label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub mandatory_indexes: Vec<usize>,
    pub selective_indexes: Vec<usize>,
    pub reveal_document: json_syntax::Object,
}

/// Creates data to be used to generate a derived proof.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata>
async fn create_disclosure_data<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    verification_method: &Multikey,
    base_signature: &Bbs2023Signature,
    selective_pointers: Vec<JsonPointerBuf>,
    presentation_header: Option<&[u8]>,
    feature_option: &DerivedFeatureOption,
) -> Result<DisclosureData, DeriveError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let document = json_syntax::to_value(unsecured_document)?
        .into_object()
        .ok_or(DeriveError::ExpectedJsonObject)?;

    let decoded_base_proof = base_signature.decode_base()?;

    let mut hmac = Hmac::<Sha256>::new_from_slice(&decoded_base_proof.hmac_key).unwrap();

    let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

    let mut combined_pointers = decoded_base_proof.mandatory_pointers.clone();
    combined_pointers.extend(selective_pointers.iter().cloned());

    let mut group_definitions = HashMap::new();
    group_definitions.insert(
        Group::Mandatory,
        Cow::Borrowed(decoded_base_proof.mandatory_pointers.as_slice()),
    );
    group_definitions.insert(
        Group::Selective,
        Cow::Borrowed(selective_pointers.as_slice()),
    );
    group_definitions.insert(Group::Combined, Cow::Borrowed(&combined_pointers));

    let canonical = canonicalize_and_group(
        loader,
        label_map_factory_function,
        group_definitions,
        unsecured_document,
    )
    .await?;

    let combined_group = canonical.groups.get(&Group::Combined).unwrap();
    let mandatory_group = canonical.groups.get(&Group::Mandatory).unwrap();
    let selective_group = canonical.groups.get(&Group::Selective).unwrap();

    let mandatory_match = &mandatory_group.matching;
    let combined_match = &combined_group.matching;
    let combined_indexes: Vec<_> = combined_match.keys().copied().collect();
    let mut mandatory_indexes = Vec::with_capacity(mandatory_match.len());
    for i in mandatory_match.keys() {
        let offset = combined_indexes.binary_search(i).unwrap();
        mandatory_indexes.push(offset);
    }

    let selective_match = &selective_group.matching;
    let mandatory_non_match = &mandatory_group.non_matching;
    let non_mandatory_indexes: Vec<_> = mandatory_non_match.keys().copied().collect();
    let mut selective_indexes = Vec::with_capacity(mandatory_match.len());
    for i in selective_match.keys() {
        let offset = non_mandatory_indexes.binary_search(i).unwrap();
        selective_indexes.push(offset);
    }

    let bbs_messages: Vec<_> = mandatory_non_match
        .values()
        .map(|quad| format!("{quad} .\n").into_bytes())
        .collect();

    let DecodedMultikey::Bls12_381(pk) = verification_method.decode()? else {
        return Err(DeriveError::InvalidPublicKey);
    };

    let bbs_proof = match (&feature_option, &decoded_base_proof.description) {
        (DerivedFeatureOption::Baseline, Bbs2023SignatureDescription::Baseline) => proof_gen(
            &pk,
            &decoded_base_proof.signature_bytes,
            &decoded_base_proof.bbs_header,
            presentation_header.as_deref(),
            &bbs_messages,
            &selective_indexes,
        )?,
        (
            DerivedFeatureOption::AnonymousHolderBinding { .. },
            Bbs2023SignatureDescription::AnonymousHolderBinding { .. },
        ) => return Err(DeriveError::UnsupportedFeature),
        (
            DerivedFeatureOption::PseudonymIssuerPid { .. },
            Bbs2023SignatureDescription::PseudonymIssuerPid { .. },
        ) => return Err(DeriveError::UnsupportedFeature),
        (
            DerivedFeatureOption::PseudonymHiddenPid { .. },
            Bbs2023SignatureDescription::PseudonymHiddenPid { .. },
        ) => return Err(DeriveError::UnsupportedFeature),
        _ => return Err(DeriveError::InvalidBaseSignature),
    };

    let reveal_document = select_json_ld(&combined_pointers, &document)?.unwrap_or_default();

    let normalizer = ssi_rdf::urdna2015::normalize(
        combined_group
            .deskolemized_quads
            .iter()
            .map(Quad::as_lexical_quad_ref),
    );
    let canonical_id_map = normalizer.into_substitution();

    let mut verifier_label_map = HashMap::new();
    for (input_label, canonical_label) in canonical_id_map {
        verifier_label_map.insert(
            canonical_label,
            canonical.label_map.get(&input_label).unwrap().clone(),
        );
    }

    Ok(DisclosureData {
        bbs_proof,
        label_map: verifier_label_map,
        mandatory_indexes,
        selective_indexes,
        reveal_document,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Group {
    Mandatory,
    Selective,
    Combined,
}
