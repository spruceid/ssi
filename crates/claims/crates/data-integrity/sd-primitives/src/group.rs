use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
};

use linked_data::IntoQuadsError;
use rdf_types::{BlankIdBuf, LexicalQuad};
use ssi_core::JsonPointerBuf;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdObject};
use ssi_rdf::{urdna2015::NormalizingSubstitution, LexicalInterpretation};

use crate::{
    canonicalize::label_replacement_canonicalize_nquads,
    select::{select_canonical_nquads, SelectError},
    skolemize::{expanded_to_deskolemized_nquads, SkolemError, Skolemize},
};

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error(transparent)]
    Skolem(#[from] SkolemError),

    #[error(transparent)]
    NQuads(#[from] IntoQuadsError),

    #[error(transparent)]
    Select(#[from] SelectError),
}

/// Canonicalize and group.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#canonicalizeandgroup>
pub async fn canonicalize_and_group<T, N>(
    loader: &impl ssi_json_ld::Loader,
    label_map_factory_function: impl FnMut(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf>,
    group_definitions: HashMap<N, Cow<'_, [JsonPointerBuf]>>,
    document: &T,
) -> Result<CanonicalizedAndGrouped<N>, GroupError>
where
    T: JsonLdObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
    N: Eq + Hash,
{
    let mut skolemize = Skolemize::default();

    let (skolemized_expanded_document, skolemized_compact_document) =
        skolemize.compact_document(loader, document).await?;

    let deskolemized_quads =
        expanded_to_deskolemized_nquads(&skolemize.urn_scheme, &skolemized_expanded_document)?;

    let (quads, label_map) =
        label_replacement_canonicalize_nquads(label_map_factory_function, &deskolemized_quads);

    let mut selection = HashMap::new();
    for (name, pointers) in group_definitions {
        selection.insert(
            name,
            select_canonical_nquads(
                loader,
                &skolemize.urn_scheme,
                &pointers,
                &label_map,
                &skolemized_compact_document,
            )
            .await?,
        );
    }

    let mut groups = HashMap::new();

    for (name, selection_result) in selection {
        let mut matching = BTreeMap::new();
        let mut non_matching = BTreeMap::new();

        let selected_quads: HashSet<_> = selection_result.quads.into_iter().collect();
        let selected_deskolemized_quads = selection_result.deskolemized_quads;

        for (i, nq) in quads.iter().enumerate() {
            if selected_quads.contains(nq) {
                matching.insert(i, nq.clone());
            } else {
                non_matching.insert(i, nq.clone());
            }
        }

        groups.insert(
            name,
            Group {
                matching,
                non_matching,
                deskolemized_quads: selected_deskolemized_quads,
            },
        );
    }

    Ok(CanonicalizedAndGrouped {
        groups,
        // skolemized_expanded_document,
        // skolemized_compact_document,
        // deskolemized_quads,
        label_map,
        quads,
    })
}

pub struct CanonicalizedAndGrouped<N> {
    pub groups: HashMap<N, Group>,
    // skolemized_expanded_document: json_ld::ExpandedDocument,
    // skolemized_compact_document: json_ld::syntax::Object,
    // deskolemized_quads: Vec<LexicalQuad>,
    pub label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub quads: Vec<LexicalQuad>,
}

pub struct Group {
    pub matching: BTreeMap<usize, LexicalQuad>,
    pub non_matching: BTreeMap<usize, LexicalQuad>,
    pub deskolemized_quads: Vec<LexicalQuad>,
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, collections::HashMap};

    use hmac::{Hmac, Mac};
    use lazy_static::lazy_static;
    use ssi_core::JsonPointerBuf;
    use ssi_json_ld::CompactJsonLd;
    use ssi_rdf::IntoNQuads;

    use crate::{canonicalize::create_hmac_id_label_map_function, HmacShaAny};

    use super::canonicalize_and_group;

    const HMAC_KEY_STRING: &str =
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

    lazy_static! {
        pub static ref CREDENTIAL: CompactJsonLd = CompactJsonLd(json_syntax::json!({
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
        }));
        pub static ref MANDATORY_POINTERS: Vec<JsonPointerBuf> = vec![
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap()
        ];
    }

    #[derive(PartialEq, Eq, Hash)]
    struct Mandatory;

    #[async_std::test]
    async fn test_canonicalize_and_group() {
        let loader = ssi_json_ld::ContextLoader::default();

        let hmac_key = hex::decode(HMAC_KEY_STRING).unwrap();
        let mut hmac = HmacShaAny::Sha256(Hmac::new_from_slice(&hmac_key).unwrap());
        let label_map_factory_function = create_hmac_id_label_map_function(&mut hmac);

        let mut group_definitions = HashMap::new();
        group_definitions.insert(Mandatory, Cow::Borrowed(MANDATORY_POINTERS.as_slice()));

        let result = canonicalize_and_group(
            &loader,
            label_map_factory_function,
            group_definitions,
            &CREDENTIAL.clone(),
        )
        .await
        .unwrap();

        const EXPECTED_NQUADS: [&str; 28] = [
			"_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
			"_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <https://www.w3.org/2018/credentials#credentialSubject> _:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 .\n",
			"_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n",
			"_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
			"_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
			"_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
			"_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
			"_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boards> _:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boards> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk .\n",
			"_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc .\n",
			"_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
			"_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
			"_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
			"_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
			"_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
			"_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
			"_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
			"_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
			"_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n"
		];

        assert_eq!(result.quads.into_nquads_lines(), EXPECTED_NQUADS);

        let expected_mandatory = [
            (0, "_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n".to_string()),
            (1, "_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <https://www.w3.org/2018/credentials#credentialSubject> _:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 .\n".to_string()),
            (2, "_:u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n".to_string()),
            (8, "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (9, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boards> _:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 .\n".to_string()),
            (11, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n".to_string()),
            (14, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk .\n".to_string()),
            (15, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc .\n".to_string()),
            (22, "_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (23, "_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (24, "_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (25, "_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (26, "_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (27, "_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string())
        ];

        let mut mandatory: Vec<_> = result
            .groups
            .get(&Mandatory)
            .unwrap()
            .matching
            .iter()
            .map(|(i, quad)| (*i, format!("{quad} .\n")))
            .collect();
        mandatory.sort_by_key(|(i, _)| *i);

        assert_eq!(mandatory, expected_mandatory);

        let expected_non_mandatory = [
            (3, "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (4, "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (5, "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (6, "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n".to_string()),
            (7, "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n".to_string()),
            (10, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boards> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n".to_string()),
            (12, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg .\n".to_string()),
            (13, "_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#sails> _:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ .\n".to_string()),
            (16, "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n".to_string()),
            (17, "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n".to_string()),
            (18, "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (19, "_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n".to_string()),
            (20, "_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (21, "_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string())
        ];

        let mut non_mandatory: Vec<_> = result
            .groups
            .get(&Mandatory)
            .unwrap()
            .non_matching
            .iter()
            .map(|(i, quad)| (*i, format!("{quad} .\n")))
            .collect();
        non_mandatory.sort_by_key(|(i, _)| *i);

        assert_eq!(non_mandatory, expected_non_mandatory);
    }
}
