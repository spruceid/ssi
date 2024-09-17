use std::{borrow::Cow, collections::HashMap};

use rdf_types::{BlankIdBuf, Quad};
use serde::Serialize;
use ssi_core::JsonPointerBuf;
use ssi_data_integrity_core::{DataIntegrity, Proof, ProofRef};
use ssi_di_sd_primitives::{
    canonicalize::create_hmac_id_label_map_function,
    group::{canonicalize_and_group, GroupError},
    select::{select_json_ld, DanglingJsonPointer},
};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdNodeObject};
use ssi_multicodec::MultiEncodedBuf;
use ssi_rdf::LexicalInterpretation;

use crate::EcdsaSd2023;

use super::{InvalidBaseSignature, Signature};

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("JSON serialization failed: {0}")]
    JsonSerialization(#[from] json_syntax::SerializeError),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("invalid base signature")]
    InvalidBaseSignature,

    #[error(transparent)]
    Group(#[from] GroupError),

    #[error("dangling JSON pointer")]
    DanglingJsonPointer,
}

impl From<InvalidBaseSignature> for DeriveError {
    fn from(_value: InvalidBaseSignature) -> Self {
        Self::InvalidBaseSignature
    }
}

impl From<DanglingJsonPointer> for DeriveError {
    fn from(_value: DanglingJsonPointer) -> Self {
        Self::DanglingJsonPointer
    }
}

pub struct DeriveOptions {
    pub selective_pointers: Vec<JsonPointerBuf>,
}

pub async fn add_derived_proof<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    options: DeriveOptions,
    base_proof: ProofRef<'_, EcdsaSd2023>,
) -> Result<DataIntegrity<json_syntax::Object, EcdsaSd2023>, DeriveError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let data = create_disclosure_data(
        loader,
        unsecured_document,
        base_proof.signature,
        options.selective_pointers,
    )
    .await?;

    let new_proof = Proof {
        context: base_proof.context.cloned(),
        type_: EcdsaSd2023,
        created: base_proof.created,
        verification_method: base_proof.verification_method.cloned(),
        proof_purpose: base_proof.proof_purpose,
        expires: base_proof.expires,
        domains: base_proof.domains.to_vec(),
        challenge: base_proof.challenge.map(ToOwned::to_owned),
        nonce: base_proof.nonce.map(ToOwned::to_owned),
        options: *base_proof.options,
        signature: Signature::encode_derived(
            &data.base_signature,
            &data.public_key,
            &data.signatures,
            &data.label_map,
            &data.mandatory_indexes,
        ),
        extra_properties: base_proof.extra_properties.clone(),
    };

    Ok(DataIntegrity::new(data.reveal_document, new_proof.into()))
}

struct DisclosureData {
    pub base_signature: Vec<u8>,
    pub public_key: MultiEncodedBuf,
    pub signatures: Vec<Vec<u8>>,
    pub label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub mandatory_indexes: Vec<usize>,
    pub reveal_document: json_syntax::Object,
}

/// Creates data to be used to generate a derived proof.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#createdisclosuredata>
async fn create_disclosure_data<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    base_signature: &Signature,
    selective_pointers: Vec<JsonPointerBuf>,
) -> Result<DisclosureData, DeriveError>
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    let document = json_syntax::to_value(unsecured_document)?
        .into_object()
        .ok_or(DeriveError::ExpectedJsonObject)?;

    let decoded_base_proof = base_signature.decode_base()?;

    let mut hmac = decoded_base_proof.hmac_key.to_hmac();

    let label_map_factory_function = create_hmac_id_label_map_function(&mut hmac);

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

    let mut mandatory_indexes = Vec::with_capacity(mandatory_group.matching.len());
    for (relative_index, absolute_index) in combined_group.matching.keys().enumerate() {
        // convert the absolute index to any mandatory quad to an index relative
        // to the combined output that is to be revealed.
        if mandatory_group.matching.contains_key(absolute_index) {
            mandatory_indexes.push(relative_index);
        }
    }

    let mut index = 0;
    let mut filtered_signatures = Vec::new();
    for signature in decoded_base_proof.signatures {
        while mandatory_group.matching.contains_key(&index) {
            index += 1
        }

        if selective_group.matching.contains_key(&index) {
            filtered_signatures.push(signature)
        }

        index += 1
    }

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
        base_signature: decoded_base_proof.base_signature,
        public_key: decoded_base_proof.public_key,
        signatures: filtered_signatures,
        label_map: verifier_label_map,
        mandatory_indexes,
        reveal_document,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Group {
    Mandatory,
    Selective,
    Combined,
}
