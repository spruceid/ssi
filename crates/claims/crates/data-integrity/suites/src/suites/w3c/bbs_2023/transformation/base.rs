use std::{borrow::Cow, collections::HashMap, hash::Hash};

use getrandom::getrandom;
use hmac::{Hmac, Mac};
use k256::sha2::Sha256;
use ssi_data_integrity_core::suite::standard::TransformationError;
use ssi_di_sd_primitives::group::canonicalize_and_group;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;

use crate::bbs_2023::{Bbs2023SignatureOptions, HmacKey};

use super::{create_shuffled_id_label_map_function, TransformedBase};

pub async fn base_proof_transformation<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    canonical_configuration: Vec<String>,
    transform_options: Bbs2023SignatureOptions,
) -> Result<TransformedBase, TransformationError>
where
    T: JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
{
    // Base Proof Transformation algorithm.
    // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
    let hmac_key = match transform_options.hmac_key {
        Some(key) => key,
        None => {
            // Generate a random key
            let mut key = HmacKey::default();
            getrandom(&mut key).map_err(TransformationError::internal)?;
            key
        }
    };

    let mut hmac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();

    let mut group_definitions = HashMap::new();
    group_definitions.insert(
        Mandatory,
        Cow::Borrowed(transform_options.mandatory_pointers.as_slice()),
    );

    let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

    let mut groups = canonicalize_and_group(
        loader,
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

    Ok(TransformedBase {
        options: transform_options,
        mandatory,
        non_mandatory,
        hmac_key,
        canonical_configuration,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Mandatory;

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, collections::HashMap};

    use hmac::{Hmac, Mac};
    use k256::sha2::Sha256;
    use ssi_data_integrity_core::{
        suite::standard::TypedTransformationAlgorithm, ProofConfiguration,
    };
    use ssi_di_sd_primitives::group::canonicalize_and_group;
    use ssi_rdf::IntoNQuads;
    use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

    use crate::{
        bbs_2023::{
            Bbs2023SignatureOptions, Bbs2023Transformation, Bbs2023TransformationOptions,
            FeatureOption, HmacKey,
        },
        Bbs2023,
    };

    use super::{super::super::tests::*, create_shuffled_id_label_map_function, Mandatory};

    #[async_std::test]
    async fn hmac_canonicalize_and_group() {
        let loader = ssi_json_ld::ContextLoader::default();

        let mut hmac_key = HmacKey::default();
        hex::decode_to_slice(HMAC_KEY_STRING.as_bytes(), &mut hmac_key).unwrap();
        let mut hmac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();

        let mut group_definitions = HashMap::new();
        group_definitions.insert(Mandatory, Cow::Borrowed(MANDATORY_POINTERS.as_slice()));

        let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

        let canonical = canonicalize_and_group(
            &loader,
            label_map_factory_function,
            group_definitions,
            &*UNSIGNED_BASE_DOCUMENT,
        )
        .await
        .unwrap();

        const EXPECTED_NQUADS: [&str; 28] = [
            "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
            "_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .\n",
            "_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n"
        ];

        assert_eq!(canonical.quads.into_nquads_lines(), EXPECTED_NQUADS)
    }

    #[async_std::test]
    async fn transform_test() {
        let context = ssi_claims_core::SignatureEnvironment::default();

        let proof_configuration = ProofConfiguration::new(
            Bbs2023,
            xsd_types::DateTime::now_ms(),
            ReferenceOrOwned::Reference("did:method:test".parse().unwrap()),
            ProofPurpose::Assertion,
            (),
        );

        let mut hmac_key = HmacKey::default();
        hex::decode_to_slice(HMAC_KEY_STRING.as_bytes(), &mut hmac_key).unwrap();

        let transformed = Bbs2023Transformation::transform(
            &context,
            &*UNSIGNED_BASE_DOCUMENT,
            proof_configuration.borrowed(),
            Bbs2023TransformationOptions::BaseSignature(Bbs2023SignatureOptions {
                mandatory_pointers: MANDATORY_POINTERS.clone(),
                feature_option: FeatureOption::Baseline,
                commitment_with_proof: None,
                hmac_key: Some(hmac_key),
            }),
        )
        .await
        .unwrap()
        .into_base()
        .unwrap();

        let expected_mandatory = [
            (0, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n".to_string()),
            (1, "_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .\n".to_string()),
            (2, "_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n".to_string()),
            (8, "_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (9, "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .\n".to_string()),
            (11, "_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n".to_string()),
            (14, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .\n".to_string()),
            (15, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .\n".to_string()),
            (22, "_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (23, "_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (24, "_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (25, "_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (26, "_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (27, "_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string())
        ];

        let expected_non_mandatory = [
            (3, "_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (4, "_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (5, "_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (6, "_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n".to_string()),
            (7, "_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n".to_string()),
            (10, "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .\n".to_string()),
            (12, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .\n".to_string()),
            (13, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .\n".to_string()),
            (16, "_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n".to_string()),
            (17, "_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n".to_string()),
            (18, "_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (19, "_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n".to_string()),
            (20, "_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (21, "_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string())
        ];

        assert_eq!(transformed.mandatory.len(), expected_mandatory.len());
        for (a, (_, b)) in transformed.mandatory.iter().zip(expected_mandatory) {
            let a = format!("{a} .\n");
            assert_eq!(a, b)
        }

        assert_eq!(
            transformed.non_mandatory.len(),
            expected_non_mandatory.len()
        );
        for (a, (_, b)) in transformed.non_mandatory.iter().zip(expected_non_mandatory) {
            let a = format!("{a} .\n");
            assert_eq!(a, b)
        }
    }
}
