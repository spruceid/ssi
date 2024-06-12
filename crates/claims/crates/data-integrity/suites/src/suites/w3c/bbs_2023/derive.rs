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
    let mut selective_indexes = Vec::with_capacity(mandatory_non_match.len());
    for i in selective_match.keys() {
        if let Ok(offset) = non_mandatory_indexes.binary_search(i) {
            selective_indexes.push(offset);
        }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use json_syntax::{Parse, UnorderedPartialEq};
    use lazy_static::lazy_static;
    use rdf_types::BlankIdBuf;
    use ssi_bbs::BBSplusPublicKey;
    use ssi_data_integrity_core::DataIntegrity;
    use ssi_di_sd_primitives::{select::select_json_ld, JsonPointerBuf};
    use ssi_json_ld::JsonLdEnvironment;
    use ssi_vc::v2::JsonCredential;
    use ssi_verification_methods::Multikey;
    use static_iref::{iri, uri};

    use crate::{bbs_2023::Bbs2023Signature, Bbs2023};

    use super::{create_disclosure_data, DerivedFeatureOption, DisclosureData};

    const PUBLIC_KEY_HEX: &str = "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f";
    const PRESENTATION_HEADER_HEX: &str = "113377aa";

    // TODO this can't be used because the BBS API (based on zkryptium) does not
    // allow providing a seed.
    // const PSEUDO_RANDOM_SEED_HEX: &str = "332e313431353932363533353839373933323338343632363433333833323739";

    const BBS_PROOF_HEX: &str = "85b72d74b55aae76e4f8e986387352f6d3e13f19387f5935a9f34c59aa3af77885501ef1dba67576bd24e6dab1b1c5b3891671112c26982c441d4f352e1bc8f5451127fbda2ad240d9a5d6933f455db741cc3e79d3281bc5b611118b363461f2b6a5ecdd423f6b76711680824665f50eec1f5cbaf219ee90e66ceac575146d1a8935f770be6d29a376b00e4e39a4fa7755ecf4eb42aa3babfd6e48bb23e91081f08d0d259b4029683d01c25378be3c61213a097750b8ce2a3c0915061a547405b3ce587d1d8299269fad29103509b3e53067f7b6078e9dc66a5112192aede3662e6dac5876d945fd05863fb249b0fca02e10ab5173650ef665e92c3ea72eaba94fca860cd6c639538e5156f8cbc3b4d222f7a11f837bb9e76ba54d58c1b4ac834ef338a3db4bf645b4622153c897f477255f40e4fcc7919348ae5bf9032a9f7c0876e47a6666ca9f178673ac7a41b864480d8e84c6655cd2f0e1866dedc467590a2ba76c28cb41f3d5582e0773b737914b8353fea4df918a022aa5aa92f490f0b3c2edf4a4d5538b8d07aa2530f118863e654eeaaac69c2c020509c24294c13bda721c73b8610bbce7e7030d1710dd5148731a5026c741d1da9e0693d32b90d09bb58a8e4a295a32fb27f654a03c31c56e6c3afb1aa3f2fa240f5095f31fe8b95f8179bc4408cf96713f3aec6a06409a6f1486a99d9923befdb274d3e04f6faa9bf316ce9a2c4f5e1bc6db031593323b";

    lazy_static! {
        static ref MANDATORY_POINTERS: [JsonPointerBuf; 5] = [
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap()
        ];
        static ref SELECTIVE_POINTERS: [JsonPointerBuf; 2] = [
            "/credentialSubject/boards/0".parse().unwrap(),
            "/credentialSubject/boards/1".parse().unwrap()
        ];
        static ref SIGNED_BASE_DOCUMENT: json_syntax::Object =
            json_syntax::Value::parse_str(include_str!("tests/signed-base-document.jsonld"))
                .unwrap()
                .0
                .into_object()
                .unwrap();
        static ref UNSIGNED_REVEAL_DOCUMENT: json_syntax::Object =
            json_syntax::Value::parse_str(include_str!("tests/unsigned-reveal-document.jsonld"))
                .unwrap()
                .0
                .into_object()
                .unwrap();
        static ref PUBLIC_KEY: BBSplusPublicKey =
            BBSplusPublicKey::from_bytes(&hex::decode(PUBLIC_KEY_HEX).unwrap()).unwrap();
        static ref PRESENTATION_HEADER: Vec<u8> = hex::decode(PRESENTATION_HEADER_HEX).unwrap();
        static ref LABEL_MAP: HashMap<BlankIdBuf, BlankIdBuf> = [
            ("_:c14n0".parse().unwrap(), "_:b2".parse().unwrap()),
            ("_:c14n1".parse().unwrap(), "_:b4".parse().unwrap()),
            ("_:c14n2".parse().unwrap(), "_:b3".parse().unwrap()),
            ("_:c14n3".parse().unwrap(), "_:b7".parse().unwrap()),
            ("_:c14n4".parse().unwrap(), "_:b6".parse().unwrap()),
            ("_:c14n5".parse().unwrap(), "_:b0".parse().unwrap())
        ]
        .into_iter()
        .collect();
        static ref BBS_PROOF: Vec<u8> = hex::decode(BBS_PROOF_HEX).unwrap();
    }

    #[test]
    fn reveal_document() {
        let mut combined_pointers = MANDATORY_POINTERS.to_vec();
        combined_pointers.extend(SELECTIVE_POINTERS.iter().cloned());

        let mut document = SIGNED_BASE_DOCUMENT.clone();
        document.remove("proof");

        let reveal_document = select_json_ld(&combined_pointers, &document)
            .unwrap()
            .unwrap_or_default();

        assert!(reveal_document.unordered_eq(&UNSIGNED_REVEAL_DOCUMENT))
    }

    #[async_std::test]
    async fn disclosure_data() {
        let signed_base: DataIntegrity<JsonCredential, Bbs2023> =
            json_syntax::from_value(json_syntax::Value::Object(SIGNED_BASE_DOCUMENT.clone()))
                .unwrap();

        let verification_method = Multikey::from_public_key(
            iri!("did:method:id").to_owned(),
            uri!("did:method:controller").to_owned(),
            &*PUBLIC_KEY,
        );

        let mut context = JsonLdEnvironment::default();

        eprintln!(
            "signature = {}",
            signed_base.proofs.first().unwrap().signature.proof_value
        );

        let data = create_disclosure_data(
            &mut context,
            &signed_base.claims,
            &verification_method,
            &signed_base.proofs.first().unwrap().signature,
            SELECTIVE_POINTERS.to_vec(),
            Some(&PRESENTATION_HEADER),
            &DerivedFeatureOption::Baseline,
        )
        .await
        .unwrap();

        assert_eq!(
            data.mandatory_indexes,
            [0, 1, 2, 5, 6, 8, 9, 10, 14, 15, 16, 17, 18, 19]
        );
        assert_eq!(data.selective_indexes, [3, 4, 5, 8, 9, 10]);

        // TODO this can't be tested because the BBS API (based on zkryptium)
        // does not allow providing a seed.
        // assert_eq!(data.bbs_proof, *BBS_PROOF);

        assert_eq!(data.label_map, *LABEL_MAP);
    }

    #[test]
    fn encode_derived() {
        let data = DisclosureData {
            bbs_proof: BBS_PROOF.clone(),
            label_map: LABEL_MAP.clone(),
            mandatory_indexes: [0, 1, 2, 5, 6, 8, 9, 10, 14, 15, 16, 17, 18, 19].to_vec(),
            selective_indexes: [3, 4, 5, 8, 9, 10].to_vec(),
            reveal_document: UNSIGNED_REVEAL_DOCUMENT.clone(),
        };

        let signature = Bbs2023Signature::encode_derived(
            &data.bbs_proof,
            &data.label_map,
            &data.mandatory_indexes,
            &data.selective_indexes,
            Some(&PRESENTATION_HEADER),
            &DerivedFeatureOption::Baseline,
        )
        .unwrap();

        assert_eq!(signature.proof_value.as_str(), "u2V0DhVkCEIW3LXS1Wq525PjphjhzUvbT4T8ZOH9ZNanzTFmqOvd4hVAe8dumdXa9JObasbHFs4kWcREsJpgsRB1PNS4byPVFESf72irSQNml1pM_RV23Qcw-edMoG8W2ERGLNjRh8ral7N1CP2t2cRaAgkZl9Q7sH1y68hnukOZs6sV1FG0aiTX3cL5tKaN2sA5OOaT6d1Xs9OtCqjur_W5IuyPpEIHwjQ0lm0ApaD0BwlN4vjxhIToJd1C4zio8CRUGGlR0BbPOWH0dgpkmn60pEDUJs-UwZ_e2B46dxmpREhkq7eNmLm2sWHbZRf0Fhj-ySbD8oC4Qq1FzZQ72ZeksPqcuq6lPyoYM1sY5U45RVvjLw7TSIvehH4N7uedrpU1YwbSsg07zOKPbS_ZFtGIhU8iX9HclX0Dk_MeRk0iuW_kDKp98CHbkemZmyp8XhnOsekG4ZEgNjoTGZVzS8OGGbe3EZ1kKK6dsKMtB89VYLgdztzeRS4NT_qTfkYoCKqWqkvSQ8LPC7fSk1VOLjQeqJTDxGIY-ZU7qqsacLAIFCcJClME72nIcc7hhC7zn5wMNFxDdUUhzGlAmx0HR2p4Gk9MrkNCbtYqOSilaMvsn9lSgPDHFbmw6-xqj8vokD1CV8x_ouV-BebxECM-WcT867GoGQJpvFIapnZkjvv2ydNPgT2-qm_MWzposT14bxtsDFZMyO6YAAgEEAgMDBwQGBQCOAAECBQYICQoODxAREhOGAwQFCAkKRBEzd6o");
    }
}
