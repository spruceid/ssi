use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use keccak_hash::keccak;
use rdf_types::QuadRef;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

use crate::{LinkedDataDocument, Proof};
use ssi_crypto::hashes::keccak::bytes_to_lowerhex;
use ssi_json_ld::{rdf::NQuadsStatement, ContextLoader};

/// Object at eip712 (formerly eip712Domain) property of [Ethereum EIP712 Signature 2021](https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021) proof object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ProofInfo {
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,
    pub primary_type: StructName,
    pub domain: EIP712Value,
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionError {
    #[error("Unable to convert document to data set: {0}")]
    DocumentToDataset(String),
    #[error("Unable to convert proof to data set: {0}")]
    ProofToDataset(String),
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionJSONError {
    #[error("Not Implemented")]
    NotImplemented,
    #[error("Unable to convert document to JSON: {0}")]
    DocumentToJSON(String),
    #[error("Unable to convert proof object to JSON: {0}")]
    ProofToJSON(String),
    #[error("Expected document to be a JSON object")]
    ExpectedDocumentObject,
    #[error("Expected proof to be a JSON object")]
    ExpectedProofObject,
    #[error("Expected types in proof.eip712")]
    ExpectedTypes,
    #[error("Unable to parse eip712: {0}")]
    ParseInfo(serde_json::Error),
    #[error("Unable to convert document to EIP-712 message: {0}")]
    ConvertMessage(TypedDataParseError),
    #[error("Unable to dereference EIP-712 types: {0}")]
    DereferenceTypes(DereferenceTypesError),
    #[error("Unable to generate EIP-712 types and proof info: {0}")]
    GenerateProofInfo(#[from] ProofGenerationError),
}

impl TypedData {
    pub async fn from_document_and_options(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
        context_loader: &mut ContextLoader,
    ) -> Result<Self, TypedDataConstructionError> {
        let doc_dataset = document
            .to_dataset_for_signing(None, context_loader)
            .await
            .map_err(|e| TypedDataConstructionError::DocumentToDataset(e.to_string()))?;
        let doc_dataset_normalized =
            crate::urdna2015::normalize(doc_dataset.quads().map(QuadRef::from));
        let mut doc_statements_normalized: Vec<_> = doc_dataset_normalized.collect();
        #[allow(clippy::redundant_closure)]
        doc_statements_normalized.sort_by_cached_key(|x| NQuadsStatement(x).to_string());
        let sigopts_dataset = proof
            .to_dataset_for_signing(Some(document), context_loader)
            .await
            .map_err(|e| TypedDataConstructionError::ProofToDataset(e.to_string()))?;
        let sigopts_dataset_normalized =
            crate::urdna2015::normalize(sigopts_dataset.quads().map(QuadRef::from));
        let mut sigopts_statements_normalized: Vec<_> = sigopts_dataset_normalized.collect();
        #[allow(clippy::redundant_closure)]
        sigopts_statements_normalized.sort_by_cached_key(|x| NQuadsStatement(x).to_string());
    }

    /// Convert linked data document and proof to TypedData according to
    /// [EthereumEip712Signature2021](https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/)
    pub async fn from_document_and_options_json(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
    ) -> Result<Self, TypedDataConstructionJSONError> {
        let mut doc_value = document
            .to_value()
            .map_err(|e| TypedDataConstructionJSONError::DocumentToJSON(e.to_string()))?;
        let doc_obj = doc_value
            .as_object_mut()
            .ok_or(TypedDataConstructionJSONError::ExpectedDocumentObject)?;
        let mut proof_value = serde_json::to_value(proof)
            .map_err(|e| TypedDataConstructionJSONError::ProofToJSON(e.to_string()))?;
        let proof_obj = proof_value
            .as_object_mut()
            .ok_or(TypedDataConstructionJSONError::ExpectedProofObject)?;
        
    }

    /// Encode a typed data message for hashing and signing.
    /// [Reference](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#specification)
    pub fn hash(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let bytes = self.bytes()?;
        let hash = keccak(bytes).to_fixed_bytes().to_vec();
        Ok(hash)
    }

    pub fn bytes(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let message_hash = hash_struct(&self.message, &self.primary_type, &self.types)?;
        let domain_separator =
            hash_struct(&self.domain, &StructName::from("EIP712Domain"), &self.types)?;

        let bytes = vec![
            vec![0x19, 0x01],
            domain_separator.to_vec(),
            message_hash.to_vec(),
        ]
        .concat();
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use serde_json::json;

    #[test]
    fn test_parse_type() {
        let string_type = EIP712Type::try_from(String::from("string")).unwrap();
        assert_eq!(string_type, EIP712Type::String);

        let string_array_type = EIP712Type::try_from(String::from("string[]")).unwrap();
        let string_array_type_expected = EIP712Type::Array(Box::new(EIP712Type::String));
        assert_eq!(string_array_type, string_array_type_expected);

        EIP712Type::try_from(String::from("string]")).unwrap_err();
    }

    #[test]
    fn test_encode_type() {
        let types = Types {
            eip712_domain: StructType(Vec::new()),
            types: vec![
                (
                    "Transaction".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "from".to_string(),
                            type_: EIP712Type::Struct("Person".to_string()),
                        },
                        MemberVariable {
                            name: "to".to_string(),
                            type_: EIP712Type::Struct("Person".to_string()),
                        },
                        MemberVariable {
                            name: "tx".to_string(),
                            type_: EIP712Type::Struct("Asset".to_string()),
                        },
                    ]),
                ),
                (
                    "Person".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "wallet".to_string(),
                            type_: EIP712Type::Address,
                        },
                        MemberVariable {
                            name: "name".to_string(),
                            type_: EIP712Type::String,
                        },
                    ]),
                ),
                (
                    "Asset".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "token".to_string(),
                            type_: EIP712Type::Address,
                        },
                        MemberVariable {
                            name: "amount".to_string(),
                            type_: EIP712Type::UintN(256),
                        },
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let type_encoded = encode_type(
            &StructName::from("Transaction"),
            types.get("Transaction").unwrap(),
            &types,
        )
        .unwrap();
        let type_encoded_string = String::from_utf8(type_encoded).unwrap();
        assert_eq!(type_encoded_string, "Transaction(Person from,Person to,Asset tx)Asset(address token,uint256 amount)Person(address wallet,string name)");
    }

    #[test]
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#example
    // https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js
    fn hash_typed_data() {
        let _addr = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";
        let typed_data: TypedData = serde_json::from_value(json!({
          "types": {
            "EIP712Domain": [
              { "name": "name", "type": "string" },
              { "name": "version", "type": "string" },
              { "name": "chainId", "type": "uint256" },
              { "name": "verifyingContract", "type": "address" }
            ],
            "Person": [
              { "name": "name", "type": "string" },
              { "name": "wallet", "type": "address" }
            ],
            "Mail": [
              { "name": "from", "type": "Person" },
              { "name": "to", "type": "Person" },
              { "name": "contents", "type": "string" }
            ]
          },
          "primaryType": "Mail",
          "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
          },
          "message": {
            "from": {
              "name": "Cow",
              "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            },
            "to": {
              "name": "Bob",
              "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            },
            "contents": "Hello, Bob!"
          }
        }))
        .unwrap();

        // Hash Type
        let struct_type = typed_data.types.get("Mail").unwrap();
        let type_encoded = encode_type(&"Mail".to_string(), struct_type, &typed_data.types)
            .unwrap()
            .to_vec();
        let type_hash = keccak(&type_encoded).to_fixed_bytes().to_vec();
        let type_encoded_string = String::from_utf8(type_encoded).unwrap();
        assert_eq!(
            type_encoded_string,
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
        assert_eq!(
            bytes_to_lowerhex(&type_hash),
            "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        );

        // Hash struct
        let data: EIP712Value = serde_json::from_value(json!({
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        }))
        .unwrap();
        let data_encoded = encode_data(
            &data,
            &EIP712Type::Struct("Person".to_string()),
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_encoded),
            "0xb9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c795008c1d2bd5348394761719da11ec67eedae9502d137e8940fee8ecd6f641ee1648000000000000000000000000cd2a3d9f938e13cd947ec05abc7fe734df8dd826"
        );

        // Encode message
        let data_encoded = encode_data(
            &typed_data.message,
            &EIP712Type::Struct(typed_data.primary_type.clone()),
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_encoded),
            "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8"
        );

        // Hash message
        let data_hashed = hash_struct(
            &typed_data.message,
            &typed_data.primary_type,
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_hashed),
            "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );

        let hash = typed_data.hash().unwrap();
        let hash_hex = bytes_to_lowerhex(&hash);
        assert_eq!(
            hash_hex,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );

        // Test more types
        let typed_data: TypedData = serde_json::from_value(json!({
            "types": {
                "EIP712Domain": [
                    { "type": "string", "name": "name" }
                ],
                "Message": [
                    { "name": "bytes8", "type": "bytes8" },
                    { "name": "bytes32", "type": "bytes32" },
                    { "name": "uint8", "type": "uint8" },
                    { "name": "uint32", "type": "uint32" },
                    { "name": "uint256", "type": "uint256" },
                    { "name": "int8", "type": "int8" },
                    { "name": "int16", "type": "int16" },
                    { "name": "true", "type": "bool" },
                    { "name": "empty", "type": "Empty[1]" },
                    { "name": "missing", "type": "Empty" },
                    { "name": "bitmatrix", "type": "bool[2][2]" }
                ],
                "Empty": [
                ]
            },
            "primaryType": "Message",
            "domain": {
                "name": "Test"
            },
            "message": {
                "bytes8": "0x0102030405060708",
                "bytes32": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f10",
                "uint8": "0x03",
                "uint32": 0x01020304,
                "uint256": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f10",
                "int8": -5,
                "int16": 5,
                "true": true,
                "empty": [{
                }],
                "bitmatrix": [
                    [true, false],
                    [false, true]
                ]
            }
        }
        ))
        .unwrap();
        let hash = typed_data.hash().unwrap();
        assert_eq!(
            bytes_to_lowerhex(&hash),
            "0x3128ae562d7141585a21f9c04e87520857ae9025d5c57293255f25d72f869b2e"
        );
    }

    lazy_static! {
            // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L637-L645
            static ref TEST_BASIC_DOCUMENT: Value = {
                json!({
                    "@context": ["https://schema.org", "https://w3id.org/security/v2"],
                    "@type": "Person",
                    "firstName": "Jane",
                    "lastName": "Does",
                    "jobTitle": "Professor",
                    "telephone": "(425) 123-4567",
                    "email": "jane.doe@example.com"
                })
            };
            // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L646-L660
            static ref TEST_NESTED_DOCUMENT: Value = {
                json!({
                    "@context": ["https://schema.org", "https://w3id.org/security/v2"],
                    "@type": "Person",
                    "data": {
                      "name": {
                        "firstName": "John",
                        "lastName": "Doe"
                      },
                      "job": {
                        "jobTitle": "Professor",
                        "employer": "University of Waterloo"
                      }
                    },
                    "telephone": "(425) 123-4567"
                })
            };

            static ref MOCK_ETHR_DID_RESOLVER: MockEthrDIDResolver =
                MockEthrDIDResolver {
                    doc: serde_json::from_value(json!({
                      "@context": [
                        "https://www.w3.org/ns/did/v1",
                        {
                          "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                          "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
                        }
                      ],
                      "id": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443",
                      "verificationMethod": [{
                          "id": "#blockchainAccountId",
                          "type": "EcdsaSecp256k1RecoveryMethod2020",
                          "controller": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443",
                          "blockchainAccountId": "eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443"
                      }],
                      "assertionMethod": [
                          "#blockchainAccountId"
                      ]
                    })).unwrap()
                };
    }

    #[test]
    fn test_property_sorting() {
        // https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.3
        let object: EIP712Value = serde_json::from_str(
            r#"{
           "\u20ac": "Euro Sign",
           "\r": "Carriage Return",
           "\ufb33": "Hebrew Letter Dalet With Dagesh",
           "1": "One",
           "\ud83d\ude00": "Emoji: Grinning Face",
           "\u0080": "Control",
           "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#,
        )
        .unwrap();
        let mut props: Vec<(&String, &EIP712Value)> = object.as_struct().unwrap().iter().collect();
        props.sort_by_cached_key(|(name, _value)| name.encode_utf16().collect::<Vec<u16>>());
        let expected_values = vec![
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let values: Vec<String> = props
            .iter()
            .map(|(_name_, value)| Value::from((*value).clone()).as_str().unwrap().to_string())
            .collect();
        assert_eq!(values, expected_values);
    }

    #[test]
    fn test_types_generation() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/25
        // #example-1
        let doc: EIP712Value = serde_json::from_value(json!({
          "@context": ["https://schema.org", "https://w3id.org/security/v2"],
          "@type": "Person",
          "name": {
            "first": "Jane",
            "last": "Doe",
          },
          "otherData": {
            "jobTitle": "Professor",
            "school": "University of ExampleLand",
          },
          "telephone": "(425) 123-4567",
          "email": "jane.doe@example.com",
        }))
        .unwrap();

        // #example-2
        let expected_types: HashMap<StructName, StructType> = serde_json::from_value(json!({
            "Name": [
              { "name": "first", "type": "string" },
              { "name": "last", "type": "string" },
            ],
            "OtherData": [
              { "name": "jobTitle", "type": "string" },
              { "name": "school", "type": "string" },
            ],
            "Document": [
              { "name": "@context", "type": "string[]" },
              { "name": "@type", "type": "string" },
              { "name": "email", "type": "string" },
              { "name": "name", "type": "Name" },
              { "name": "otherData", "type": "OtherData" },
              { "name": "telephone", "type": "string" },
            ]
        }))
        .unwrap();
        let types = generate_types(&doc, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        let expected_types_value = serde_json::to_value(expected_types).unwrap();
        assert_eq!(types_value, expected_types_value);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26
        let test_basic_document: EIP712Value =
            serde_json::from_value(TEST_BASIC_DOCUMENT.clone()).unwrap();
        let types = generate_types(&test_basic_document, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        let expected_types_value: Value = json!({
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]"
                },
                {
                  "name": "@type",
                  "type": "string"
                },
                {
                  "name": "email",
                  "type": "string"
                },
                {
                  "name": "firstName",
                  "type": "string"
                },
                {
                  "name": "jobTitle",
                  "type": "string"
                },
                {
                  "name": "lastName",
                  "type": "string"
                },
                {
                  "name": "telephone",
                  "type": "string"
                }
              ]
        });
        assert_eq!(types_value, expected_types_value);
    }

    use async_trait::async_trait;
    use ssi_dids::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
    };
    use ssi_dids::Document;

    use crate::{DataSet, LinkedDataProofOptions};
    use ssi_core::uri::URI;
    use ssi_dids::VerificationRelationship as ProofPurpose;

    #[async_std::test]
    async fn eip712sig_keypair() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/4f1a089c109c32e29725254accfc375588736c39/index.html#L480-L483
        let addr = "0xaed7ea8035eec47e657b34ef5d020c7005487443";
        let sk_hex = "0x149195a4059ac8cafe2d56fc612f613b6b18b9265a73143c9f6d7cfbbed76b7e";
        let sk_bytes = bytes_from_hex(sk_hex).unwrap();
        use ssi_jwk::{Base64urlUInt, ECParams, Params, JWK};

        let sk = k256::SecretKey::from_be_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();
        let mut ec_params = ECParams::try_from(&pk).unwrap();
        ec_params.ecc_private_key = Some(Base64urlUInt(sk_bytes.to_vec()));
        let jwk = JWK::from(Params::EC(ec_params));
        let hash = ssi_jwk::eip155::hash_public_key(&jwk).unwrap();
        assert_eq!(hash, addr);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct InputOptions {
        #[serde(skip_serializing_if = "Option::is_none")]
        types: Option<HashMap<StructName, StructType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        domain: Option<EIP712Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        date: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "embed")]
        embed: Option<bool>,
        #[serde(rename = "embedAsURI")]
        #[serde(skip_serializing_if = "Option::is_none")]
        embed_as_uri: Option<bool>,
    }
    impl From<InputOptions> for LinkedDataProofOptions {
        fn from(input_options: InputOptions) -> LinkedDataProofOptions {
            LinkedDataProofOptions {
                created: input_options.date,
                verification_method: Some(URI::String(
                    "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443".to_string(),
                )),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            }
        }
    }

    struct ExampleDocument(Value);
    #[async_trait]
    impl LinkedDataDocument for ExampleDocument {
        fn get_contexts(&self) -> Result<Option<String>, crate::error::Error> {
            Ok(None)
        }
        async fn to_dataset_for_signing(
            &self,
            _parent: Option<&(dyn LinkedDataDocument + Sync)>,
            _context_loader: &mut ContextLoader,
        ) -> Result<DataSet, crate::error::Error> {
            todo!();
        }

        fn to_value(&self) -> Result<Value, crate::error::Error> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockEthrDIDResolver {
        doc: Document,
    }
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for MockEthrDIDResolver {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            let doc: Document = match did {
                "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443" => self.doc.clone(),
                _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
            };
            (
                ResolutionMetadata::default(),
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }

    // 3.6. Test Vectors
    // https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#test-vectors
    // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26

    /// 3.6.1. Basic Document - Types Generation - No Embedding
    /// #basic-document-types-generation-no-embedding
    #[async_std::test]
    #[ignore] // FIXME
    async fn eip712sig_types_generation_no_embedding() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L673-L679
        let input_options: InputOptions = serde_json::from_value(json!({
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          }
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L685-L691
        let proof: Proof = serde_json::from_value(json!({
            "created": "2021-08-30T13:28:02Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "0xbbdf2914c7572185bbc263e066dfb43f3136e4441fddb3fe3ea4541bbf7fd1f00d8e5af3ce4fbb1f2ebd5256f39b22cef7f285189df2976ea0c385c77f0a42791b",
            "type": "EthereumEip712Signature2021",
            "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        }))
        .unwrap();

        let basic_doc = ExampleDocument(TEST_BASIC_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&basic_doc, &resolver, &mut context_loader)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    /// 3.6.2. Nested Document - TypedData Provided - Embedded EIP712 Properties
    /// #nested-document-typeddata-provided-embedded-types
    async fn eip712sig_typeddata_provided_embedded_eip712_properties() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L703-L782
        let input_options: InputOptions = serde_json::from_value(json!({
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "types": {
            "Data": [
              {
                "name": "job",
                "type": "Job"
              },
              {
                "name": "name",
                "type": "Name"
              }
            ],
            "Document": [
              {
                "name": "@context",
                "type": "string[]"
              },
              {
                "name": "@type",
                "type": "string"
              },
              {
                "name": "data",
                "type": "Data"
              },
              {
                "name": "telephone",
                "type": "string"
              },
              {
                "name": "proof",
                "type": "Proof"
              }
            ],
            "Job": [
              {
                "name": "employer",
                "type": "string"
              },
              {
                "name": "jobTitle",
                "type": "string"
              }
            ],
            "Proof": [
              {
                "name": "created",
                "type": "string"
              },
              {
                "name": "proofPurpose",
                "type": "string"
              },
              {
                "name": "type",
                "type": "string"
              },
              {
                "name": "verificationMethod",
                "type": "string"
              }
            ],
            "Name": [
              {
                "name": "firstName",
                "type": "string"
              },
              {
                "name": "lastName",
                "type": "string"
              }
            ]
          },
          "domain": {
            "name": "Test"
          },
          "date": "2021-08-30T13:28:02Z",
          "embed": true
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L788-L872
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "eip712": {
            "domain": {
              "name": "Test",
            },
            "primaryType": "Document",
            "types": {
              "Data": [
                {
                  "name": "job",
                  "type": "Job",
                },
                {
                  "name": "name",
                  "type": "Name",
                },
              ],
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]",
                },
                {
                  "name": "@type",
                  "type": "string",
                },
                {
                  "name": "data",
                  "type": "Data",
                },
                {
                  "name": "telephone",
                  "type": "string",
                },
                {
                  "name": "proof",
                  "type": "Proof",
                },
              ],
              "Job": [
                {
                  "name": "employer",
                  "type": "string",
                },
                {
                  "name": "jobTitle",
                  "type": "string",
                },
              ],
              "Name": [
                {
                  "name": "firstName",
                  "type": "string",
                },
                {
                  "name": "lastName",
                  "type": "string",
                },
              ],
              "Proof": [
                {
                  "name": "created",
                  "type": "string",
                },
                {
                  "name": "proofPurpose",
                  "type": "string",
                },
                {
                  "name": "type",
                  "type": "string",
                },
                {
                  "name": "verificationMethod",
                  "type": "string",
                },
              ],
            },
          },
          "proofPurpose": "assertionMethod",
          "proofValue": "0xcf5844be1f1a5c1a083565d492ab4bee93bd0e24a4573bd8ff47331ad225b9d11c4831aade8d071f4abb8c9e266aaaf30612c582c2bc8f082b8788448895fa4a1b",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    /// 3.6.3. Nested Document - Types Generation - TypedData Schema as URI
    /// #nested-document-types-generation-typeddata-schema-as-uri
    async fn eip712sig_typeddata_types_generation_typeddata_schema_as_uri() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L885-L892
        let input_options: InputOptions = serde_json::from_value(json!({
          "embedAsURI": true,
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          }
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L898-L911
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "proofPurpose": "assertionMethod",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "proofValue": "0x8327ad5e4b2426eac7626400c75f000c3e04caf2a863b888988e4e85533880183d4b9cc6870183e55dabfa96b9486624f45ef849bb146257d123f297a2dbf3a11c",
          "eip712": {
            "domain": {
              "name": "Test"
            },
            "types": "https://example.org/types.json",
            "primaryType": "Document"
          }
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // Types generation
        let test_nested_document: EIP712Value =
            serde_json::from_value(TEST_NESTED_DOCUMENT.clone()).unwrap();
        let types = generate_types_with_proof(&test_nested_document, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        assert_eq!(types_value, *EXAMPLE_TYPES);
    }

    #[async_std::test]
    /// 3.6.4. Nested Document - Types Generation - Types Embedded
    /// #nested-document-types-generation-types-embedded
    async fn eip712sig_typeddata_provided_embedded_types() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L983-L990
        let input_options: InputOptions = serde_json::from_value(json!({
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          },
          "embed": true
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L996-L1080
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "eip712": {
            "domain": {
              "name": "EthereumEip712Signature2021",
            },
            "primaryType": "Document",
            "types": {
              "Data": [
                {
                  "name": "job",
                  "type": "Job",
                },
                {
                  "name": "name",
                  "type": "Name",
                },
              ],
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]",
                },
                {
                  "name": "@type",
                  "type": "string",
                },
                {
                  "name": "data",
                  "type": "Data",
                },
                {
                  "name": "proof",
                  "type": "Proof",
                },
                {
                  "name": "telephone",
                  "type": "string",
                },
              ],
              "Job": [
                {
                  "name": "employer",
                  "type": "string",
                },
                {
                  "name": "jobTitle",
                  "type": "string",
                },
              ],
              "Name": [
                {
                  "name": "firstName",
                  "type": "string",
                },
                {
                  "name": "lastName",
                  "type": "string",
                },
              ],
              "Proof": [
                {
                  "name": "created",
                  "type": "string",
                },
                {
                  "name": "proofPurpose",
                  "type": "string",
                },
                {
                  "name": "type",
                  "type": "string",
                },
                {
                  "name": "verificationMethod",
                  "type": "string",
                },
              ],
            },
          },
          "proofPurpose": "assertionMethod",
          "proofValue": "0x7d57ace2be9cc3944aac023f66130935e489bbb1c9b469a4a5b4f16e5c298b57291bc80d52c6f873b11f4bf45c97c6e2506419af7506eaac5374e9ed381fcc5b1b",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }
}
