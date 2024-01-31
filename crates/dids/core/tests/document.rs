// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn parse_did_url() {
//         // https://w3c.github.io/did-core/#example-3-a-did-url-with-a-service-did-parameter
//         let didurl_str = "did:foo:21tDAKCERh95uGgKbJNHYp?service=agent";
//         let didurl = DIDURL::try_from(didurl_str.to_string()).unwrap();
//         assert_eq!(
//             didurl,
//             DIDURL {
//                 did: "did:foo:21tDAKCERh95uGgKbJNHYp".to_string(),
//                 path_abempty: "".to_string(),
//                 query: Some("service=agent".to_string()),
//                 fragment: None,
//             }
//         );
//     }

//     #[test]
//     fn did_url_relative_to_absolute() {
//         // https://w3c.github.io/did-core/#relative-did-urls
//         let relative_did_url_str = "#key-1";
//         let did_url_ref = RelativeDIDURL::from_str(relative_did_url_str).unwrap();
//         let did = "did:example:123456789abcdefghi";
//         let did_url = did_url_ref.to_absolute(did);
//         assert_eq!(did_url.to_string(), "did:example:123456789abcdefghi#key-1");
//     }

//     #[test]
//     fn new_document() {
//         let id = "did:test:deadbeefcafe";
//         let doc = Document::new(id);
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//         assert_eq!(doc.id, id);
//     }

//     #[test]
//     fn build_document() {
//         let id = "did:test:deadbeefcafe";
//         let doc = DocumentBuilder::default()
//             .id(id.to_owned())
//             .build()
//             .unwrap();
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//         assert_eq!(doc.id, id);
//     }

//     #[test]
//     #[should_panic(expected = "Missing document ID")]
//     fn build_document_no_id() {
//         let doc = DocumentBuilder::default().build().unwrap();
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//     }

//     #[test]
//     #[should_panic(expected = "Invalid context")]
//     fn build_document_invalid_context() {
//         let id = "did:test:deadbeefcafe";
//         let doc = DocumentBuilder::default()
//             .context(Contexts::One(Context::URI("example:bad".parse().unwrap())))
//             .id(id)
//             .build()
//             .unwrap();
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//     }

//     #[test]
//     fn document_from_json() {
//         let doc_str = "{\
//             \"@context\": \"https://www.w3.org/ns/did/v1\",\
//             \"id\": \"did:test:deadbeefcafe\"\
//         }";
//         let id = "did:test:deadbeefcafe";
//         let doc = Document::from_json(doc_str).unwrap();
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//         assert_eq!(doc.id, id);
//     }

//     #[test]
//     fn verification_method() {
//         let id = "did:test:deadbeefcafe";
//         let mut doc = Document::new(id);
//         doc.verification_method = Some(vec![VerificationMethod::DIDURL(
//             DIDURL::try_from("did:pubkey:okay".to_string()).unwrap(),
//         )]);
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//         let pko = VerificationMethodMap {
//             id: String::from("did:example:123456789abcdefghi#keys-1"),
//             type_: String::from("Ed25519VerificationKey2018"),
//             controller: String::from("did:example:123456789abcdefghi"),
//             ..Default::default()
//         };
//         doc.verification_method = Some(vec![
//             VerificationMethod::DIDURL(DIDURL::try_from("did:pubkey:okay".to_string()).unwrap()),
//             VerificationMethod::Map(pko),
//         ]);
//         println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//         assert_eq!(doc.id, id);
//     }

//     #[test]
//     fn vmm_to_jwk() {
//         // Identity: publicKeyJWK -> JWK
//         const JWK: &str = include_str!("../../tests/ed25519-2020-10-18.json");
//         let jwk: JWK = serde_json::from_str(JWK).unwrap();
//         let pk_jwk = jwk.to_public();
//         let vmm_ed = VerificationMethodMap {
//             id: String::from("did:example:foo#key2"),
//             type_: String::from("Ed25519VerificationKey2018"),
//             controller: String::from("did:example:foo"),
//             public_key_jwk: Some(pk_jwk.clone()),
//             ..Default::default()
//         };
//         let jwk = vmm_ed.get_jwk().unwrap();
//         assert_eq!(jwk, pk_jwk);
//     }

//     #[test]
//     fn vmm_bs58_to_jwk() {
//         // publicKeyBase58 (deprecated) -> JWK
//         const JWK: &str = include_str!("../../tests/ed25519-2020-10-18.json");
//         let jwk: JWK = serde_json::from_str(JWK).unwrap();
//         let pk_jwk = jwk.to_public();
//         let vmm_ed = VerificationMethodMap {
//             id: String::from("did:example:foo#key3"),
//             type_: String::from("Ed25519VerificationKey2018"),
//             controller: String::from("did:example:foo"),
//             public_key_base58: Some("2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH".to_string()),
//             ..Default::default()
//         };
//         let jwk = vmm_ed.get_jwk().unwrap();
//         assert_eq!(jwk, pk_jwk);
//     }

//     #[test]
//     fn vmm_hex_to_jwk() {
//         // publicKeyHex (deprecated) -> JWK
//         const JWK: &str = include_str!("../../tests/secp256k1-2021-02-17.json");
//         let jwk: JWK = serde_json::from_str(JWK).unwrap();
//         let pk_jwk = jwk.to_public();
//         let vmm_ed = VerificationMethodMap {
//             id: String::from("did:example:deprecated#lds-ecdsa-secp256k1-2019-pkhex"),
//             type_: String::from("EcdsaSecp256k1VerificationKey2019"),
//             controller: String::from("did:example:deprecated"),
//             public_key_jwk: Some(pk_jwk.clone()),
//             ..Default::default()
//         };
//         let jwk = vmm_ed.get_jwk().unwrap();
//         assert_eq!(jwk, pk_jwk);
//     }
// }
