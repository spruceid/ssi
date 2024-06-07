use ssi_json_ld::{JsonLdProcessor, RemoteDocument};
use lazy_static::lazy_static;
use linked_data::to_lexical_quads;
use rdf_types::{generator, LexicalQuad, Quad};
use ssi_bbs::{BBSplusPublicKey, BBSplusSecretKey};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_rdf::{urdna2015, IntoNQuads};

const PUBLIC_KEY_HEX: &str = "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f";
const SECRET_KEY_HEX: &str = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0";
const HMAC_KEY_STRING: &str = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

lazy_static! {
    pub static ref PUBLIC_KEY: BBSplusPublicKey =
        BBSplusPublicKey::from_bytes(&hex::decode(PUBLIC_KEY_HEX).unwrap()).unwrap();
    pub static ref SECRET_KEY: BBSplusSecretKey =
        BBSplusSecretKey::from_bytes(&hex::decode(SECRET_KEY_HEX).unwrap()).unwrap();
    pub static ref CREDENTIAL: json_ld::syntax::Value = json_syntax::json!({
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
    });
    pub static ref MANDATORY_POINTERS: Vec<JsonPointerBuf> = vec![
        "/issuer".parse().unwrap(),
        "/credentialSubject/sailNumber".parse().unwrap(),
        "/credentialSubject/sails/1".parse().unwrap(),
        "/credentialSubject/boards/0/year".parse().unwrap(),
        "/credentialSubject/sails/2".parse().unwrap()
    ];
}

async fn to_rdf(document: json_ld::syntax::Value) -> Vec<LexicalQuad> {
    let document: RemoteDocument = RemoteDocument::new(None, None, document);
    let expanded_document = document
        .expand(&mut ssi_json_ld::ContextLoader::default())
        .await
        .unwrap();

    to_lexical_quads(&mut generator::Blank::new(), &expanded_document).unwrap()
}

async fn canonicalize_document(document: json_ld::syntax::Value) -> Vec<LexicalQuad> {
    let quads = to_rdf(document).await;
    urdna2015::normalize(quads.iter().map(Quad::as_lexical_quad_ref)).collect()
}

#[async_std::test]
async fn bbs_canonicalization() {
    const EXPECTED: [&str; 28] = [
		"_:c14n0 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
		"_:c14n0 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
		"_:c14n0 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
		"_:c14n1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
		"_:c14n1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n2 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
		"_:c14n2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
		"_:c14n2 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n3 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
		"_:c14n3 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n3 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n4 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
		"_:c14n4 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
		"_:c14n4 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n0 .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n2 .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n1 .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n3 .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n4 .\n",
		"_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n6 .\n",
		"_:c14n6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
		"_:c14n6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
		"_:c14n6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"_:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
		"_:c14n7 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 .\n",
		"_:c14n7 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n"
	];

    let canonical_quads = canonicalize_document(CREDENTIAL.clone())
        .await
        .into_nquads_lines();
    assert_eq!(canonical_quads, EXPECTED);
}

// #[async_std::test]
// async fn bbs_hmac_canonicalization() {
//   const EXPECTED: [&str; 28] = [
//     "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
//     "_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .\n",
//     "_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n",
//     "_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
//     "_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
//     "_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
//     "_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
//     "_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .\n",
//     "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .\n",
//     "_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
//     "_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
//     "_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
//     "_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
//     "_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
//     "_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
//     "_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
//     "_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
//     "_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n"
//   ];

//   let mut hmac = Hmac::new_from_slice(HMAC_KEY_STRING.as_bytes()).unwrap();

//   let label_map_factory_function = create_shuffled_id_label_map_function(&mut hmac);

//   // let mut environment = ssi_json_ld::JsonLdEnvironment::default();
// 	// let canonical = canonicalize(
//   //   &mut environment,
//   //   label_map_factory_function,
//   //   &ssi_json_ld::CompactJsonLd(CREDENTIAL.clone())
//   // ).await.unwrap();

//   // let canonical_nquads = canonical.quads.into_nquads_lines();

//   let quads = to_rdf(CREDENTIAL.clone()).await;
//   let hmac_nquads = label_replacement_canonicalize_nquads(label_map_factory_function, &quads).0.into_nquads_lines();

//   for line in &hmac_nquads {
//     print!("{}", line)
//   }

// 	assert_eq!(hmac_nquads, EXPECTED);
// }

// fn key_pair() -> (BBSplusPublicKey, BBSplusSecretKey) {
// 	(
// 		BBSplusPublicKey::from_bytes(&hex::decode(PUBLIC_KEY_HEX).unwrap()).unwrap(),
// 		BBSplusSecretKey::from_bytes(&hex::decode(SECRET_KEY_HEX).unwrap()).unwrap()
// 	)
// }
