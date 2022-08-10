use async_recursion::async_recursion;
use chrono::DateTime;
use serde::Deserialize;
use serde_bytes::Bytes;
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

    let mut prefix: Vec<u8> = vec![25, 4, 1, 88, 34];
    let mut suffix: &str;
    if did_url.starts_with(DID_V1) {
        suffix = did_url.split_at(DID_V1.len()).1;
    } else {
        suffix = did_url.split_at(DID_KEY.len()).1;
    }

    let to_decode: Vec<&str> = suffix.split('#').collect();
    let decode = to_decode[0];
    let dec = &decode[1..];
    let mut did_url_encoded = bs58::decode(dec).into_vec().unwrap();
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
        println!("value encoded: {:?}", value_encoded);
    }

    if value_string.starts_with("urn:uuid:") {
        let urnuuid_bytes = encode_urnuuid(val.clone());
        value_encoded = urnuuid_bytes.to_vec();
        println!("value encoded: {:?}", value_encoded);
    }

    if value_string.starts_with("did:key") {
        value_encoded = encode_base_58_did_url(val.clone());
        println!("value encoded: {:?}", value_encoded);
    }

    if value_string.starts_with("z") {
        value_encoded = encode_multi_base(val.clone());
        println!("value encoded: {:?}", value_encoded);
    }

    let is_it_a_date = DateTime::parse_from_rfc3339(value_string);
    if is_it_a_date.is_ok() {
        value_encoded = encode_xsd_datetime(val.clone());
        println!("value encoded: {:?}", value_encoded);
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

        println!("----------------------------------------");
        println!("key: {:?}, value: {:?}", key, value);
        println!("encoded key: {:?}", key_encoded);

        if value.is_array() {
            let nested_value = value.as_array().unwrap().clone();
            let key_encoded_plural = key_encoded + 1;
            println!("encoded key plural: {:?}", key_encoded_plural);

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
                        println!("term value encoded: {:?}", value_encoded);
                    }
                }
                if val.is_number() {
                    let value_encoded = val;
                }
            }

            transform_map.insert(key_encoded_plural, value_array);

            println!("----------------------------------------");
        } else if value.is_string() {
            let known_key_word = key_map.get(value.as_str().unwrap());
            if known_key_word.is_none() {
                let value_encoded = encode_string_value(value.clone());
                transform_map.insert(key_encoded.clone(), value_encoded);
            } else {
                let value_encoded = encode_vocab_term(value.clone(), key_map.clone());
                println!("term value encoded: {:?}", value_encoded);
                transform_map.insert(key_encoded.clone(), value_encoded);
            }
        } else if value.is_object() {
            let embedded_transform_map =
                truage_jsonld_to_cborld(value.clone(), transform_maps.clone()).await;

            for map in embedded_transform_map {
                transform_maps.push(map.clone());
            }
        }
    }
    println!("----------------------------------------");
    transform_maps.push(transform_map.clone());
    results.push(transform_map);
    //println!("transform_maps {:?}", transform_maps);

    // let compressed_object = serde_cbor::ser::to_vec(&transform_maps);
    // println!("compressed_object {:?}", compressed_object);
    println!("results len {:?}", transform_maps.len());

    //println!("results: {:?}", results);

    transform_maps
}

pub async fn encode(document: Value) {
    let mut transform_maps = vec![];
    let mut result = truage_jsonld_to_cborld(document, transform_maps).await;

    println!("RESULT LEN  {:?}", result.len());
    for value in result.clone() {
        println!("result item {:?}", value);
    }

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
            suffix = vec![88, 83];
            suffix.append(&mut value);
        } else {
            suffix = value;
        }
        //to do: add overage = 21 properly
        let mut appendix = vec![24, 148, 21];
        compressed_credential_subject_array.append(&mut prefix);
        compressed_credential_subject_array.append(&mut suffix);
        compressed_credential_subject_array.append(&mut appendix);
    }

    //hacking together the map structure
    let mut compressed_proof_array: Vec<u8> = vec![];
    let map_indicator1: u8 = (level_three_object_1.len() + 160).try_into().unwrap();
    compressed_credential_subject_array.push(map_indicator1);
    for (key, mut value) in level_three_object_1 {
        let mut prefix = vec![24, key];
        let mut suffix: Vec<u8> = vec![];

        if value.len() == 1 {
            suffix = vec![24, value[0]];
        } else if key == 192 {
            suffix = vec![88, 65];
            suffix.append(&mut value);
        } else {
            suffix = vec![131];
            suffix.append(&mut value);
        }

        compressed_proof_array.append(&mut prefix);
        compressed_proof_array.append(&mut suffix);
    }

    level_two.insert(114, compressed_proof_array);
    level_two.insert(158, compressed_credential_subject_array);

    let mut compressed_vc_array: Vec<u8> = vec![];
    let map_indicator3: u8 = (level_two.len() + 160).try_into().unwrap();
    compressed_vc_array.push(129);
    compressed_vc_array.push(map_indicator3);
    for (key, mut value) in level_two {
        let mut prefix = vec![24, key];
        let mut suffix = vec![];

        if value.len() == 1 || value.len() == 2 || value.len() == 3 {
            suffix = vec![(value.len() + 128).try_into().unwrap()];
            suffix.append(&mut value);
        } else {
            suffix = value;
        }

        compressed_vc_array.append(&mut prefix);
        compressed_vc_array.append(&mut suffix);
    }

    level_one.insert(125, compressed_vc_array);

    let mut final_result: Vec<u8> = vec![];
    let mut cbor_indicator: Vec<u8> = vec![217, 5, 1];
    let map_indicator4: u8 = (level_one.len() + 160).try_into().unwrap();
    final_result.append(&mut cbor_indicator);
    final_result.push(map_indicator4);

    for (key, value) in level_one {
        println!("level_one_entry key: {:?}, value: {:?}", key, value);
        let mut prefix = vec![24, key];
        let mut suffix = value;

        final_result.append(&mut prefix);
        final_result.append(&mut suffix);
    }

    // println!("final result: {:?}", final_result);
    // println!("final result length {:?}", final_result.len());
}

// tests will fail without the correct json_ld document input
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[async_std::test]
    async fn test_cbor_compression() {
        let doc: Value = serde_json::from_str(
            r#"{
                "@context": [
                    "https://www.w3.org/2018/credentials/v1"
                ],
            }
            "#,
        )
        .unwrap();

        let document = process_json_to_json_ld_document(doc);

        //To do: build up term_id_map with custom terms
        let term_to_id_map = get_keywordsmap();

        //CONTEXT
        let context_encoded = encode_context(document.context[0].as_str().unwrap());
        let context_tuple = (1, context_encoded);

        let mut context_btree_map: BTreeMap<i32, Vec<u8>> = BTreeMap::new();
        context_btree_map.insert(context_tuple.0, context_tuple.1);
        let context_result = serde_cbor::ser::to_vec_packed(&context_btree_map);
        println!("context_result: {:?}", context_result);

        //URNUUID
        let uuid = encode_urnuuid(document.id);
        let uuid_bytes = Bytes::new(&uuid);
        let uuid_tuple = (3, uuid_bytes);

        let urn_uuid_tuple = (112, uuid_tuple);
        let uuid_result = serde_cbor::ser::to_vec_packed(&urn_uuid_tuple);
        println!("uuid_result: {:?}", uuid_result);

        //TYPE = VerifiablePresentation
        let vocab_term_id = encode_vocab_term(document.type_, term_to_id_map.clone());
        let type_tuple = (117, vec![vocab_term_id]);
        let type_result = serde_cbor::ser::to_vec(&type_tuple);
        println!("type_result {:?}", type_result);

        // verifiablecredential
        //1, 112, 114, 117, 158, 162, 164, 166
        let mut verifiable_credential_map = BTreeMap::new();
        let vc_context: Vec<u8> = vec![17, 22, 20];
        let context_byte = Bytes::new(&[17, 22, 20]);
        verifiable_credential_map.insert(1, vc_context); //values for context urls

        let verifiable_credential = document.verifiable_credential.as_array().unwrap();

        let vc_id = verifiable_credential[0]["id"].clone();
        let vc_uuid = encode_urnuuid(vc_id);
        let vc_uuid_byte = Bytes::new(&vc_uuid);
        let vc_uuid_tuple = (3, vc_uuid_byte);

        let vc_uuid_result = serde_cbor::ser::to_vec(&vc_uuid_tuple).unwrap();
        let vc_uuid_result_byte = Bytes::new(&vc_uuid_result);

        verifiable_credential_map.insert(112, vc_uuid_result.clone()); //values for urn:uuid

        let vc_proof_doc = verifiable_credential[0]["proof"].clone();
        let vc_proof = process_json_to_proof(vc_proof_doc); // value map for proof

        let vc_proof_type = vc_proof.type_;
        let vc_proof_type_encoded = encode_vocab_term(vc_proof_type, term_to_id_map.clone());
        let vc_proof_type_bytes = Bytes::new(&vc_proof_type_encoded);

        let vc_proof_created = vc_proof.created;
        let vc_proof_created_encoded = encode_xsd_datetime(vc_proof_created);
        let vc_proof_created_bytes = Bytes::new(&vc_proof_created_encoded);

        let vc_proof_purpose = vc_proof.proof_purpose;
        let vc_proof_purpose_encoded = encode_vocab_term(vc_proof_purpose, term_to_id_map.clone());
        let vc_proof_purpose_bytes = Bytes::new(&vc_proof_purpose_encoded);

        let vc_proof_value = vc_proof.proof_value;
        let vc_proof_value_encoded = encode_multi_base(vc_proof_value);
        let vc_proof_value_bytes = Bytes::new(&vc_proof_value_encoded);

        let vc_proof_verification_method = vc_proof.verification_method;
        let vc_proof_verification_method_encoded =
            encode_base_58_did_url(vc_proof_verification_method);
        let vc_proof_verification_method_bytes = Bytes::new(&vc_proof_verification_method_encoded);

        let vc_type = verifiable_credential[0]["type"].clone();
        let vc_type_encoded = encode_vocab_term(vc_type, term_to_id_map.clone());
        let vc_type_bytes = Bytes::new(&vc_type_encoded);
        verifiable_credential_map.insert(117, vc_type_encoded.clone()); // values for vc_type

        let vc_credential_subject = verifiable_credential[0]["credentialSubject"].clone();
        //let mut vc_credential_subject_map: BTreeMap<i32, Vec<u8>> = BTreeMap::new();                                  // value map for credentialSubject

        let credential_subject = process_json_to_credential_subject(vc_credential_subject);

        //let vc_over_age = credential_subject.over_age;
        //let vc_over_age_byte = encode_vocab_term(vc_over_age, term_to_id_map.clone());
        let over_age_tuple = (148, 21);
        let vc_over_age_result = serde_cbor::ser::to_vec(&over_age_tuple); // value for over_age

        let vc_concealed_id_token = credential_subject.concealed_id_token;
        let vc_concealed_id_bytes = encode_multi_base(vc_concealed_id_token);
        let vc_concealed_id_result = Bytes::new(&vc_concealed_id_bytes); // value for concealed ID token

        let vc_expiration = verifiable_credential[0]["expirationDate"].clone();
        let vc_expiration_encoded = encode_xsd_datetime(vc_expiration); // values for expiration date

        let vc_issuance = verifiable_credential[0]["issuanceDate"].clone();
        let vc_issuance_encoded = encode_xsd_datetime(vc_issuance); // values for issuance date

        let vc_issuer = verifiable_credential[0]["issuer"].clone();
        let vc_issuer_encoded = encode_base_58_did_url(vc_issuer);

        //compress veriableCredential
        let vc_result = serde_cbor::ser::to_vec(&verifiable_credential_map);
    }

    #[async_std::test]
    async fn test_general() {
        let doc: Value = serde_json::from_str(
            r#"{
                "@context": [
                    "https://www.w3.org/2018/credentials/v1"
                ],
            }
            "#,
        )
        .unwrap();

        encode(doc).await;
    }
}
