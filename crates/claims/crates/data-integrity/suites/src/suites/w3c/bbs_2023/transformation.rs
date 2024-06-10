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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hmac::{Hmac, Mac};
    use k256::sha2::Sha256;
    use lazy_static::lazy_static;
    use ssi_data_integrity_core::{
        suite::standard::TypedTransformationAlgorithm, ProofConfiguration,
    };
    use ssi_di_sd_primitives::{group::canonicalize_and_group, JsonPointerBuf};
    use ssi_json_ld::JsonLdEnvironment;
    use ssi_rdf::IntoNQuads;
    use ssi_vc::v2::syntax::JsonCredential;
    use ssi_verification_methods::{ProofPurpose, ReferenceOrOwned};

    use crate::{
        bbs_2023::{Bbs2023InputOptions, FeatureOption, HmacKey},
        Bbs2023,
    };

    use super::{create_shuffled_id_label_map_function, Bbs2023Transformation, Mandatory};

    const HMAC_KEY_STRING: &str =
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

    lazy_static! {
        pub static ref CREDENTIAL: JsonCredential = json_syntax::from_value(json_syntax::json!({
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {
                "@vocab": "https://windsurf.grotto-networking.com/selective#"
              }
            ],
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "https://vc.example/windsurf/racecommittee",
            "credentialSubject": {
              "sailNumber": "Earth101",
              "sails": [
                {
                  "size": 5.5,
                  "sailName": "Kihei",
                  "year": 2023
                },
                {
                  "size": 6.1,
                  "sailName": "Lahaina",
                  "year": 2023
                },
                {
                  "size": 7.0,
                  "sailName": "Lahaina",
                  "year": 2020
                },
                {
                  "size": 7.8,
                  "sailName": "Lahaina",
                  "year": 2023
                }
              ],
              "boards": [
                {
                  "boardName": "CompFoil170",
                  "brand": "Wailea",
                  "year": 2022
                },
                {
                  "boardName": "Kanaha Custom",
                  "brand": "Wailea",
                  "year": 2019
                }
              ]
            }
        }))
        .unwrap();
        pub static ref MANDATORY_POINTERS: Vec<JsonPointerBuf> = vec![
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap()
        ];
    }

    #[async_std::test]
    async fn hmac_canonicalize_and_group() {
        let mut context = JsonLdEnvironment::default();

        let mut hmac_key = HmacKey::default();
        hex::decode_to_slice(HMAC_KEY_STRING.as_bytes(), &mut hmac_key).unwrap();
        let mut hmac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();

        let mut group_definitions = HashMap::new();
        group_definitions.insert(Mandatory, MANDATORY_POINTERS.clone());

        let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

        let canonical = canonicalize_and_group(
            &mut context,
            label_map_factory_function,
            group_definitions,
            &*CREDENTIAL,
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

        for quad in &canonical.quads {
            eprintln!("{quad} .");
        }

        assert_eq!(canonical.quads.into_nquads_lines(), EXPECTED_NQUADS)
    }

    #[async_std::test]
    async fn transform_test() {
        let mut context = JsonLdEnvironment::default();

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
            &mut context,
            &*CREDENTIAL,
            proof_configuration.borrowed(),
            Some(Bbs2023InputOptions {
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
