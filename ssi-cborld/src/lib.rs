use async_recursion::async_recursion;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, vec};
use uuid::Uuid;

pub const DID_KEY: &str = "did:key:";
pub const DID_V1: &str = "did:v1:nym";

pub fn get_contextmap() -> HashMap<String, u8> {
    let contextmap = HashMap::<String, u8>::from([
        (String::from("https://www.w3.org/ns/activitystreams"), 0x10),
        (String::from("https://www.w3.org/2018/credentials/v1"), 0x11),
        (String::from("https://www.w3.org/ns/did/v1"), 0x12),
        (
            String::from("https://w3id.org/security/suites/ed25519-2018/v1"),
            0x13,
        ),
        (
            String::from("https://w3id.org/security/suites/ed25519-2020/v1"),
            0x14,
        ),
        (String::from("https://w3id.org/cit/v1"), 0x15),
        (String::from("https://w3id.org/age/v1"), 0x16),
        (
            String::from("https://w3id.org/security/suites/x25519-2020/v1"),
            0x17,
        ),
        (String::from("https://w3id.org/veres-one/v1"), 0x18),
        (String::from("https://w3id.org/webkms/v1"), 0x19),
        (String::from("https://w3id.org/zcap/v1"), 0x1A),
        (
            String::from("https://w3id.org/security/suites/hmac-2019/v1"),
            0x1B,
        ),
        (
            String::from("https://w3id.org/security/suites/aes-2019/v1"),
            0x1C,
        ),
        (String::from("https://w3id.org/vaccination/v1"), 0x1D),
        (
            String::from("https://w3id.org/vc-revocation-list-2020/v1"),
            0x1E,
        ),
        (String::from("https://w3id.org/dcc/v1c"), 0x1F),
        (String::from("https://w3id.org/vc/status-list/v1"), 0x20),
    ]);
    return contextmap;
}

pub fn get_keywordsmap() -> HashMap<String, u8> {
    let keywords = HashMap::<String, u8>::from([
        (String::from("@context"), 0),
        (String::from("@type"), 2),
        (String::from("@id"), 4),
        (String::from("@value"), 6),
        (String::from("@direction"), 8),
        (String::from("@graph"), 10),
        (String::from("@graph"), 12),
        (String::from("@index"), 14),
        (String::from("@json"), 16),
        (String::from("@language"), 18),
        (String::from("@list"), 20),
        (String::from("@nest"), 22),
        (String::from("@reverse"), 24),
        //digitalbazaar might remove the following
        (String::from("@base"), 26),
        (String::from("@container"), 28),
        (String::from("@default"), 30),
        (String::from("@embed"), 32),
        (String::from("@explicit"), 34),
        (String::from("@none"), 36),
        (String::from("@omitDefault"), 38),
        (String::from("@prefix"), 40),
        (String::from("@preserve"), 42),
        (String::from("@protected"), 44),
        (String::from("@requireAll"), 46),
        (String::from("@set"), 48),
        (String::from("@version"), 50),
        (String::from("@vocab"), 52),
        //Hardcoded for Truage implementation
        (String::from("EcdsaSecp256k1Signature2019"), 100),
        (String::from("EcdsaSecp256r1Signature2019"), 102),
        (String::from("Ed25519Signature2018"), 104),
        (String::from("RsaSignature2018"), 106),
        (String::from("VerifiableCredential"), 108),
        (String::from("VerifiablePresentation"), 110),
        (String::from("id"), 112),
        (String::from("proof"), 114),
        (String::from("type"), 116),
        (String::from("cred"), 118),
        (String::from("holder"), 120),
        (String::from("sec"), 122),
        (String::from("verifiableCredential"), 124),
        (String::from("AgeVerificationContainerCredential"), 126),
        (String::from("AgeVerificationCredential"), 128),
        (String::from("OverAgeTokenCredential"), 130),
        (String::from("PersonalPhotoCredential"), 132),
        (String::from("VerifiableCredentialRefreshService2021"), 134),
        (String::from("anchoredRes&ource"), 136),
        (String::from("concealedIdToken"), 138),
        (String::from("description"), 140),
        (String::from("digestMultibase"), 142),
        (String::from("image"), 144),
        (String::from("name"), 146),
        (String::from("overAge"), 148),
        (String::from("Ed25519Signature2020"), 150),
        (String::from("Ed25519VerificationKey2020"), 152),
        (String::from("credentialSchema"), 154),
        (String::from("credentialStatus"), 156),
        (String::from("credentialSubject"), 158),
        (String::from("evidence"), 160),
        (String::from("expirationDate"), 162),
        (String::from("issuanceDate"), 164),
        (String::from("issued"), 166),
        (String::from("issuer"), 168),
        (String::from("refreshService"), 170),
        (String::from("termsOfUse"), 172),
        (String::from("validForm"), 174),
        (String::from("validUntil"), 176),
        (String::from("xsd"), 178),
        (String::from("challenge"), 180),
        (String::from("created"), 182),
        (String::from("domain"), 184),
        (String::from("expires"), 186),
        (String::from("nonce"), 188),
        (String::from("proofPurpose"), 190),
        (String::from("proofValue"), 192),
        (String::from("verificationMethod"), 194),
        (String::from("assertionMethod"), 196),
        (String::from("authentication"), 198),
        (String::from("capabilityDelegation"), 200),
        (String::from("capabilityInvocation"), 202),
        (String::from("keyAgreement"), 204),
    ]);
    return keywords;
}

#[derive(Deserialize, Debug, Clone)]
pub struct JsonldDocument {
    context: Value,
    id: Value,
    type_: Value,
    verifiable_credential: Value,
}

pub struct CredentialSubject {
    over_age: Value,
    concealed_id_token: Value,
}

pub struct Proof {
    type_: Value,
    created: Value,
    verification_method: Value,
    proof_purpose: Value,
    proof_value: Value,
}

#[derive(Debug, Clone)]
pub struct Entry {
    aliases: Aliases,
    context: Value,
    scoped_context_map: HashMap<String, Value>,
    term_map: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Aliases {
    id: String,
    type_: String,
}

fn encode_context(context: &str) -> (Vec<u8>) {
    let context_map = get_contextmap();
    if context_map.contains_key(&context.to_string()) {
        let value = context_map.get(&context.to_string()).unwrap();
        let result = value.clone();
        vec![result]
    } else {
        vec![0]
    }
}

fn encode_urnuuid(urn_uuid: Value) -> [u8; 16] {
    let substrings: Vec<&str> = urn_uuid.as_str().unwrap().split(':').collect();
    let bare_uuid = substrings.last().unwrap().clone();
    let uuid = Uuid::parse_str(bare_uuid).unwrap();
    let uuid_bytes = uuid.as_bytes().clone();
    uuid_bytes
}

fn encode_vocab_term(terms: Value, term_to_id_map: HashMap<String, u8>) -> Vec<u8> {
    let is_array = terms.is_array();
    let mut term_array = vec![];

    if is_array {
        for term in terms.as_array().unwrap() {
            let term_string = term.as_str().unwrap().to_string();
            let bare_term = term_string.replace("\"", "");
            let term_id = term_to_id_map.get(&bare_term).unwrap();
            term_array.push(term_id.clone());
        }
    } else {
        let term_string = terms.as_str().unwrap().to_string();
        let bare_term = term_string.replace("\"", "");
        let term_id = term_to_id_map.get(&bare_term).unwrap();
        term_array.push(term_id.clone());
    }
    term_array
}

fn encode_xsd_datetime(value: Value) -> Vec<u8> {
    let iso_date = DateTime::parse_from_rfc3339(value.as_str().unwrap()).unwrap();
    let system_time: SystemTime = iso_date.into();
    let secs_since_epoch = system_time.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let xsd_result = serde_cbor::ser::to_vec(&secs_since_epoch).unwrap();
    xsd_result
}

fn encode_multi_base(value: Value) -> Vec<u8> {
    let value_string = value.as_str().unwrap();
    let mut multi_base_bytes: Vec<u8> = vec![];

    if value_string.chars().next().unwrap() == 'z' {
        multi_base_bytes.push(0x7a);
        let to_decode = &value_string[1..];
        let mut decoded = bs58::decode(to_decode).into_vec().unwrap();
        multi_base_bytes.append(&mut decoded);
    } else if value_string.chars().next().unwrap() == 'M' {
        multi_base_bytes.push(0x4d);
        let to_decode = &value_string[1..];
        let mut decoded = base64::decode(to_decode).unwrap();
        multi_base_bytes.append(&mut decoded);
    }
    multi_base_bytes
}

fn encode_base_58_did_url(value: Value) -> Vec<u8> {
    let did_url = value.as_str().unwrap();

    let mut prefix: Vec<u8> = vec![25, 4, 1];
    let mut suffix: &str;
    if did_url.starts_with(DID_V1) {
        suffix = did_url.split_at(DID_V1.len()).1;
    } else {
        suffix = did_url.split_at(DID_KEY.len()).1;
    }

    let to_decode: Vec<&str> = suffix.split('#').collect();
    let mut did_url_encoded: Vec<u8> = vec![];
    for s in to_decode {
        let dec = &s[1..];
        let mut did = bs58::decode(dec).into_vec().unwrap();
        did_url_encoded.append(&mut vec![88, 34]);
        did_url_encoded.append(&mut did);
    }

    let mut did_url: Vec<u8> = vec![];
    did_url.append(&mut prefix);
    did_url.append(&mut did_url_encoded);
    did_url
}

pub fn process_json_to_json_ld_document(doc: Value) -> JsonldDocument {
    //To do: Process more than one document at a time
    let context = doc["@context"].clone();
    let id = doc["id"].clone();
    let type_ = doc["type"].clone();
    let verifiable_credential = doc["verifiableCredential"].clone();

    let jsonld_document: JsonldDocument = JsonldDocument {
        context: context,
        id: id,
        type_: type_,
        verifiable_credential,
    };
    jsonld_document
}

pub fn process_json_to_credential_subject(doc: Value) -> CredentialSubject {
    let over_age = doc["overAge"].clone();
    let concealed_id_token = doc["concealedIdToken"].clone();

    let credential_subject = CredentialSubject {
        over_age: over_age,
        concealed_id_token: concealed_id_token,
    };
    credential_subject
}

pub fn process_json_to_proof(doc: Value) -> Proof {
    let type_: Value = doc["type"].clone();
    let created: Value = doc["created"].clone();
    let verification_method: Value = doc["verificationMethod"].clone();
    let proof_purpose: Value = doc["proofPurpose"].clone();
    let proof_value: Value = doc["proofValue"].clone();

    let proof = Proof {
        type_: type_,
        created: created,
        verification_method: verification_method,
        proof_purpose: proof_purpose,
        proof_value: proof_value,
    };
    proof
}

pub fn encode_string_value(val: Value) -> Vec<u8> {
    let value_string = val.as_str().unwrap();
    let mut value_encoded: Vec<u8> = vec![];

    if value_string.starts_with("https:/") {
        value_encoded = encode_context(value_string.clone());
    }

    if value_string.starts_with("urn:uuid:") {
        let urnuuid_bytes = encode_urnuuid(val.clone());
        value_encoded = urnuuid_bytes.to_vec();
    }

    if value_string.starts_with("did:key") || value_string.starts_with("did:v1") {
        value_encoded = encode_base_58_did_url(val.clone());
    }

    if value_string.starts_with("z") {
        value_encoded = encode_multi_base(val.clone());
    }

    let is_it_a_date = DateTime::parse_from_rfc3339(value_string);
    if is_it_a_date.is_ok() {
        value_encoded = encode_xsd_datetime(val.clone());
    }

    value_encoded
}

#[async_recursion(?Send)]
pub async fn truage_jsonld_to_cborld(
    document: Value,
    mut transform_maps: Vec<BTreeMap<u8, Vec<u8>>>,
) -> Vec<BTreeMap<u8, Vec<u8>>> {
    let doc = document.as_object().unwrap();
    let key_map = get_keywordsmap();
    let mut transform_map = BTreeMap::<u8, Vec<u8>>::new();
    let mut results = vec![];

    for (key, value) in doc {
        let key_encoded = key_map.get(&key.to_string()).unwrap();

        if value.is_array() {
            let nested_value = value.as_array().unwrap().clone();
            let key_encoded_plural = key_encoded + 1;

            let mut value_array: Vec<u8> = vec![];

            for val in nested_value {
                if val.is_object() {
                    let embedded_transform_map =
                        truage_jsonld_to_cborld(val.clone(), transform_maps.clone()).await;
                    for map in embedded_transform_map {
                        transform_maps.push(map.clone());
                    }
                }

                if val.is_string() {
                    let known_key_word = key_map.get(val.as_str().unwrap());
                    if known_key_word.is_none() {
                        let value_encoded = encode_string_value(val.clone());
                        value_array.append(&mut value_encoded.clone());
                    } else {
                        let value_encoded = encode_vocab_term(val.clone(), key_map.clone());
                        value_array.append(&mut value_encoded.clone());
                    }
                }
                //to do
                if val.is_number() {
                    let value_encoded = val;
                }
            }

            transform_map.insert(key_encoded_plural, value_array);
        } else if value.is_string() {
            let known_key_word = key_map.get(value.as_str().unwrap());
            if known_key_word.is_none() {
                let value_encoded = encode_string_value(value.clone());
                transform_map.insert(key_encoded.clone(), value_encoded);
            } else {
                let value_encoded = encode_vocab_term(value.clone(), key_map.clone());
                transform_map.insert(key_encoded.clone(), value_encoded);
            }
        } else if value.is_object() {
            let embedded_transform_map =
                truage_jsonld_to_cborld(value.clone(), transform_maps.clone()).await;

            for map in embedded_transform_map {
                transform_maps.push(map.clone());
            }
        } else if value.is_number() {
            let val = vec![value.as_u64().unwrap() as u8];
            transform_map.insert(key_encoded.clone(), val);
        }
    }
    transform_maps.push(transform_map.clone());
    results.push(transform_map);

    transform_maps
}

pub async fn encode(document: Value) -> Vec<u8> {
    let transform_maps = vec![];
    let mut result = truage_jsonld_to_cborld(document, transform_maps).await;
    let mut level_one = result.pop().unwrap();
    let mut level_two = result.pop().unwrap();
    let level_three_object_1 = result.pop().unwrap();
    let level_three_object_2 = result.pop().unwrap();

    let mut compressed_credential_subject_array: Vec<u8> = vec![];
    let map_indicator2: u8 = (level_three_object_2.len() + 160).try_into().unwrap();
    compressed_credential_subject_array.push(map_indicator2);
    for (key, mut value) in level_three_object_2 {
        let mut prefix = vec![24, key];
        let mut suffix = vec![];
        if key == 138 {
            suffix = vec![88, value.len() as u8];
            suffix.append(&mut value);
        } else if key == 148 {
            if value == vec![65] {
                prefix = vec![24, key, 24];
                suffix = value;
            } else if value == vec![21] {
                suffix = value;
            }
        } else {
            suffix = value;
        }
        compressed_credential_subject_array.append(&mut prefix);
        compressed_credential_subject_array.append(&mut suffix);
    }

    //hacking together the map structure
    //to do: refactor these hardcoded values to generalize
    let mut compressed_proof_array: Vec<u8> = vec![];
    let map_indicator1: u8 = (level_three_object_1.len() + 160).try_into().unwrap();
    compressed_proof_array.push(map_indicator1);
    for (key, mut value) in level_three_object_1 {
        let mut prefix = vec![24, key];
        let mut suffix: Vec<u8> = vec![];

        if value.len() == 1 {
            suffix = vec![24, value[0]];
        } else if key == 192 {
            suffix = vec![88, 65];
            suffix.append(&mut value);
        } else if key == 194 {
            suffix = vec![131];
            suffix.append(&mut value);
        } else {
            suffix = value;
        }

        compressed_proof_array.append(&mut prefix);
        compressed_proof_array.append(&mut suffix);
    }

    level_two.insert(114, compressed_proof_array);
    level_two.insert(158, compressed_credential_subject_array);

    let mut compressed_vc_array: Vec<u8> = vec![];
    let map_indicator3: u8 = (level_two.len() + 160).try_into().unwrap();
    // compressed_vc_array.push(129);
    compressed_vc_array.push(map_indicator3);
    for (key, mut value) in level_two {
        let mut prefix = vec![24, key];
        let mut suffix = vec![];

        if key == 1 {
            prefix = vec![key];
            suffix = vec![(value.len() + 128).try_into().unwrap()];
            suffix.append(&mut value);
        } else if key == 117 {
            suffix = vec![(value.len() + 128).try_into().unwrap()];
            for val in value {
                suffix.append(&mut vec![24, val])
            }
        } else if key == 112 {
            suffix = vec![130, 3, 80];
            suffix.append(&mut value);
        } else if key == 168 {
            prefix = vec![24, key];
            suffix = vec![130];
            suffix.append(&mut value);
        } else {
            suffix = value;
        }

        compressed_vc_array.append(&mut prefix);
        compressed_vc_array.append(&mut suffix);
    }

    level_one.insert(124, compressed_vc_array);

    let mut final_result: Vec<u8> = vec![];
    let mut cbor_indicator: Vec<u8> = vec![217, 5, 1];
    let map_indicator4: u8 = (level_one.len() + 160).try_into().unwrap();
    final_result.append(&mut cbor_indicator);
    final_result.push(map_indicator4);

    for (key, value) in level_one {
        // println!("level_one_entry key: {:?}, value: {:?}", key, value);

        let mut prefix = vec![];
        let mut suffix = vec![];
        if key == 0 {
            prefix = vec![key];
            suffix = value;
        } else if key == 1 {
            prefix = vec![key, 129];
            suffix = value;
        } else if key == 112 {
            prefix = vec![24, key, 130, 3, 80];
            suffix = value;
        } else if key == 116 {
            prefix = vec![24, key];
            for val in value {
                suffix.append(&mut vec![24, val])
            }
        } else if key == 117 {
            prefix = vec![24, key, 129];
            for val in value {
                suffix.append(&mut vec![24, val])
            }
        } else {
            prefix = vec![24, key];
            suffix = value;
        }
        // println!("prefix: {:?}, suffix: {:?}\n\n", prefix, suffix);

        final_result.append(&mut prefix);
        final_result.append(&mut suffix);
    }

    final_result
}

// tests will fail without the correct json_ld document input
#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_general() {
        let cmp_hex = hex::decode("d90501a300111874186e187ca801831116141870820350188e8450269e11ebb545d3692cf353981872a51874189618b61a610efcda18be18c418c058417abc243faceeb32327cf8afe87f7ef7d743983c588ef3d06c59f14914f0ea096d836f6fe8202c07f79c8aff0f664d276d37f170eeb742e425334fd0824af26e60c18c2831904015822ed01597d5ac5de5cdb08efcc29850df0d3fc935190b86eabbeb5eb06884db6a3aeec5822ed01597d5ac5de5cdb08efcc29850df0d3fc935190b86eabbeb5eb06884db6a3aeec187582186c1882189ea2188a58537ad90501a401150904074a7ad90501a2011605184108583b7a0000abd6420d628c532176ef0dd720df748248b808d4b9425c8f45ab44b5029feaca278d4fcd2d48cdf617fdac0f99681757fc8de74afda52e2418941518a21a60d4e4f718a41a605b9af718a8821904015822ed01597d5ac5de5cdb08efcc29850df0d3fc935190b86eabbeb5eb06884db6a3aeec").unwrap();

        let doc: Value = serde_json::json!({
          "@context": "https://www.w3.org/2018/credentials/v1",
          "type": "VerifiablePresentation",
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/age/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": "urn:uuid:188e8450-269e-11eb-b545-d3692cf35398",
            "type": [
              "VerifiableCredential",
              "OverAgeTokenCredential"
            ],
            "issuer": "did:key:z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF",
            "issuanceDate": "2021-03-24T20:03:03Z",
            "expirationDate": "2021-06-24T20:03:03Z",
            "credentialSubject": {
              "overAge": 21,
              "concealedIdToken": "zo58FV8vqzY2ZqLT4fSaVhe7CsdBKsUikBMbKridqSyc7LceLmgWcNTeHm2gfvgjuNjrVif1G2A5EKx2eyNkSu5ZBc6gNnjF8ZkV3P8dPrX8o46SF"
            },
            "proof": {
              "type": "Ed25519Signature2020",
              "created": "2021-08-07T21:36:26Z",
              "verificationMethod": "did:key:z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF#z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF",
              "proofPurpose": "assertionMethod",
              "proofValue": "z4mAs9uHU16jR4xwPcbhHyRUc6BbaiJQE5MJwn3PCWkRXsriK9AMrQQMbjzG9XXFPNgngmQXHKUz23WRSu9jSxPCF"
            }
          }
        });

        let cborld_encoded = encode(doc).await;

        // println!("OURS HEX = {}", hex::encode(cborld_encoded.clone()));
        // println!("LEN={}|OURS={:?}", cborld_encoded.len(), cborld_encoded);
        // println!("LEN={}|THEM={:?}", cmp_hex.len(), cmp_hex);

        // if cborld_encoded.len() == cmp_hex.len() {
        //     for (i, v) in cmp_hex.iter().enumerate() {
        //         let cmp = cborld_encoded[i];
        //         if cmp != *v {
        //             println!("DIFF at [{}] expected {}; got {}", i, v, cmp);
        //         }
        //     }
        // }
        assert_eq!(cborld_encoded, cmp_hex);
    }

    #[async_std::test]
    async fn test_app() {
        let cmp_hex = hex::decode("d90501a300111874186e187ca8018311161418708203509f5ff197d6d44a3da68234fc799667431872a51874189618b61a637bbeed18be18c418c058417a1d84ac2b75c2ccfaf8e57cc7bc94df9b7314291a43eb0d57ead4dfdf2f0575a76046c510e889196afef3e949692262fde8dbfc5b525f72f9126c4e0fec1b460418c2831904015822ed0191fb716a4a661ec5fb6436b3f6225ebfc10a7eda60d2b4bb5e6fb3ecfbb1207f5822ed0191fb716a4a661ec5fb6436b3f6225ebfc10a7eda60d2b4bb5e6fb3ecfbb1207f187582186c1882189ea2188a58587ad90501a40015186a1864186c4b7ad90501a20016187c1841186e583b7a00009a3e130c62d700e40a8388a3a3ac4f8df1aed0e596d32ebdc528e223443e9a1ccb24fbc19480ec9ce03937e4548b5cc12a9c2d0634ed3fc01894184118a21a63f508ec18a41a637bbeec18a8821904015822ed0191fb716a4a661ec5fb6436b3f6225ebfc10a7eda60d2b4bb5e6fb3ecfbb1207f").unwrap();

        let doc: Value = serde_json::json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiablePresentation",
            "verifiableCredential": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/age/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ],
                "id": "urn:uuid:9f5ff197-d6d4-4a3d-a682-34fc79966743",
                "type": [
                    "VerifiableCredential",
                    "OverAgeTokenCredential"
                ],
                "issuer": "did:key:z6MkpH7YDw3LBmqTmUzifCBe999t8DatvWnpxSgYQn9UEeyc",
                "issuanceDate": "2022-11-21T18:09:48Z",
                "expirationDate": "2023-02-21T18:09:48Z",
                "credentialSubject": {
                    "overAge": 65,
                    "concealedIdToken": "zPwe8eWs7Gv9pfQ2UL6y17BfCNYFx2fiHGqChnf4jK5wdtH6EgeBM6jNshNYvBYkZjudjGWyEyi5zjBVBkMtdgN7V7AKnL5BSGcxi25KpGk6KQDP9mRKHfWw"
                },
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": "2022-11-21T18:09:49Z",
                    "verificationMethod": "did:key:z6MkpH7YDw3LBmqTmUzifCBe999t8DatvWnpxSgYQn9UEeyc#z6MkpH7YDw3LBmqTmUzifCBe999t8DatvWnpxSgYQn9UEeyc",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "zbEKA8bqX3cYWJ5cYEQztNy9m3pR1L3QyDxoKcu7jXWyWz8NzKvbtpeWFnzReLAoWD2exshvto1fxbf7H7H6Vfsh"
                }
            }
        });

        let cborld_encoded = encode(doc).await;

        // println!("OURS HEX = {}", hex::encode(cborld_encoded.clone()));
        // println!("LEN={}|OURS={:?}", cborld_encoded.len(), cborld_encoded);
        // println!("LEN={}|THEM={:?}", cmp_hex.len(), cmp_hex);

        // if cborld_encoded.len() == cmp_hex.len() {
        //     for (i, v) in cmp_hex.iter().enumerate() {
        //         let cmp = cborld_encoded[i];
        //         if cmp != *v {
        //             println!("DIFF at [{}] expected {}; got {}", i, v, cmp);
        //         }
        //     }
        // }
        assert_eq!(cborld_encoded, cmp_hex);
    }
}
