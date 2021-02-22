use std::collections::HashMap;
use std::convert::TryFrom;
use std::num::ParseIntError;
use std::str::FromStr;

use keccak_hash::keccak;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ldp::LinkedDataDocument;
use crate::vc::Proof;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "String", into = "String")]
pub enum Type {
    Bytes,
    String,
    BytesN(u16),
    UintN(u16),
    IntN(u16),
    Bool,
    Address,
    Array(Box<Type>),
    ArrayN(Box<Type>, u16),
    Reference(String),
}

#[derive(Error, Debug)]
pub enum TypedDataParseError {
    // #[error("Unknown data type: {0}")]
    // UnknownType(String),
    #[error("Unable to parse data type size: {0}")]
    SizeParse(#[from] ParseIntError),
}

impl TryFrom<String> for Type {
    type Error = TypedDataParseError;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        match &string[..] {
            "bytes" => return Ok(Type::Bytes),
            "string" => return Ok(Type::String),
            "address" => return Ok(Type::Address),
            "bool" => return Ok(Type::Bool),
            _ => {}
        }
        if string.starts_with("uint") {
            return Ok(Type::UintN(u16::from_str(&string[4..])?));
        } else if string.starts_with("int") {
            return Ok(Type::IntN(u16::from_str(&string[3..])?));
        } else if string.starts_with("bytes") {
            return Ok(Type::BytesN(u16::from_str(&string[5..])?));
        } else if string.ends_with("]") {
            let mut parts = string.rsplitn(2, "[");
            let amount_str = parts.next().unwrap().split("]").next().unwrap();
            let base = Type::try_from(parts.next().unwrap().to_string())?;
            if amount_str.len() == 0 {
                return Ok(Type::Array(Box::new(base)));
            } else {
                return Ok(Type::ArrayN(Box::new(base), u16::from_str(amount_str)?));
            }
        }
        Ok(Type::Reference(string))
    }
}

impl From<Type> for String {
    fn from(type_: Type) -> String {
        match type_ {
            Type::Bytes => String::from("bytes"),
            Type::String => String::from("string"),
            Type::BytesN(n) => format!("bytes{}", n),
            Type::UintN(n) => format!("uint{}", n),
            Type::IntN(n) => format!("int{}", n),
            Type::Bool => String::from("address"),
            Type::Address => String::from("address"),
            Type::Array(type_) => format!("{}[]", String::from(*type_)),
            Type::ArrayN(type_, n) => format!("{}[{}]", String::from(*type_), n),
            Type::Reference(string) => string,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Member {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: Type,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Struct(Vec<Member>);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Types {
    // TODO: collapse eip712_domain into hashmap
    #[serde(rename = "EIP712Domain")]
    eip712_domain: Struct,
    #[serde(flatten)]
    types: HashMap<String, Struct>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Data {
    Struct(HashMap<String, Data>),
    Array(Vec<Data>),
    String(String),
    Bytes(Vec<u8>),
    Bool(bool),
    NegativeNumber(i32),
    Number(u32),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypedData {
    pub types: Types,
    pub primary_type: String,
    pub domain: Data,
    pub message: Data,
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionError {
    #[error("Unable to convert document to data set: {0}")]
    DocumentToDataset(String),
    #[error("Unable to convert proof to data set: {0}")]
    ProofToDataset(String),
    #[error("Unable to normalize document: {0}")]
    NormalizeDocument(String),
    #[error("Unable to normalize proof: {0}")]
    NormalizeProof(String),
}

#[derive(Error, Debug)]
pub enum TypedDataHashError {
    #[error("Error parsing types: {0}")]
    Parse(TypedDataParseError),
    #[error("Missing primary type struct")]
    MissingPrimaryTypeStruct,
    #[error("Missing referenced type: {0}")]
    MissingReferencedType(String),
    #[error("Missing defined type: {0}")]
    MissingDefinedType(String),
    #[error("Expected reference type for '{0}'")]
    ExpectedReference(String),
    #[error("Not implemented")]
    NotImplemented,
}

lazy_static! {
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-domainseparator>
    pub static ref EIP712_DOMAIN: Struct = {
        Struct(vec![
            Member {
                name: "name".to_string(),
                type_: Type::String
            },
            Member {
                name: "version".to_string(),
                type_: Type::String
            },
            Member {
                name: "chainId".to_string(),
                type_: Type::UintN(256)
            },
            Member {
                name: "verifyingContract".to_string(),
                type_: Type::Address
            },
            Member {
                name: "salt".to_string(),
                type_: Type::BytesN(32)
            }
        ])
    };
}

impl Struct {
    /// [`encodeType`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-encodetype)
    pub fn encode(&self, name: &str, more_types: &Types) -> Result<Vec<u8>, TypedDataHashError> {
        let mut string = String::new();
        self.encode_single(name, &mut string);
        let mut referenced_types = HashMap::new();
        self.gather_referenced_types(more_types, &mut referenced_types)?;
        let mut types: Vec<(&String, &Struct)> = referenced_types.into_iter().collect();
        types.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));
        for (name, type_) in types {
            type_.encode_single(name, &mut string);
        }
        Ok(string.into_bytes())
    }

    fn encode_single(&self, name: &str, string: &mut String) {
        string.push_str(&name);
        string.push('(');
        let mut first = true;
        for member in &self.0 {
            if first {
                first = false;
            } else {
                string.push(',');
            }
            string.push_str(&String::from(member.type_.clone()));
            string.push(' ');
            string.push_str(&member.name);
        }
        string.push(')');
    }

    fn gather_referenced_types<'a>(
        &'a self,
        types: &'a Types,
        memo: &mut HashMap<&'a String, &'a Struct>,
    ) -> Result<(), TypedDataHashError> {
        for member in &self.0 {
            if let Type::Reference(ref reference_name) = member.type_ {
                use std::collections::hash_map::Entry;
                let entry = memo.entry(reference_name);
                if let Entry::Vacant(o) = entry {
                    let referenced_struct = types.types.get(reference_name).ok_or(
                        TypedDataHashError::MissingReferencedType(reference_name.to_string()),
                    )?;
                    o.insert(referenced_struct);
                    referenced_struct.gather_referenced_types(types, memo)?;
                }
            }
        }
        Ok(())
    }
}

impl Data {
    /// [`hashStruct`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-hashstruct)
    pub fn hash(
        &self,
        type_: &Struct,
        name: &str,
        more_types: &Types,
    ) -> Result<[u8; 32], TypedDataHashError> {
        let encoded_data = self.encode(type_, more_types)?.to_vec();
        let encoded_type = type_.encode(name, more_types)?;
        let type_hash = keccak(encoded_type).to_fixed_bytes().to_vec();
        Ok(keccak(vec![type_hash, encoded_data].concat()).to_fixed_bytes())
    }

    /// [`encodeData`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-encodedata)
    pub fn encode(&self, _type: &Struct, _types: &Types) -> Result<Vec<u8>, TypedDataHashError> {
        Err(TypedDataHashError::NotImplemented)
        /*
        let enc = match self {
            Data::Struct(map) => {
                let mut enc = Vec::with_capacity(32 * type_.0.len());
                for member in &type_.0 {
                    / *
                    let member_encoded = value.encode(member_type, types)?;
                    enc.extend_from_slice(&mut member_encoded);
                    * /
                    eprintln!("member {:?}", member);
                    let value =
                        map.get(&member.name)
                            .ok_or(TypedDataHashError::MissingDefinedType(
                                member.name.to_string(),
                            ))?;
                    eprintln!("value {:?}", value);
                    let member_struct = if let Type::Reference(ref reference_name) = member.type_ {
                        types.types.get(reference_name).ok_or(
                            TypedDataHashError::MissingReferencedType(reference_name.to_string()),
                        )?
                    } else {
                        / *
                            return Err(TypedDataHashError::ExpectedReference(
                                member.name.to_string(),
                            ))
                        }
                        * /
                    };
                    eprintln!("memstruct {:?}", member_struct);
                    let mut member_hash = value.hash(member_struct, &member.name, types)?;
                    enc.extend_from_slice(&mut member_hash);
                }
                // TODO: check that no extra types in map
                enc
            }
            Data::Array(array) => {
                let mut enc = Vec::with_capacity(32 * array.len());
                for data in array {
                    // enc.push(data.encode())
                }
                enc
            }
            Data::String(string) => keccak(string.as_bytes()).to_fixed_bytes().to_vec(),
            Data::Bytes(bytes) => keccak(bytes).to_fixed_bytes().to_vec(),
            Data::Bool(true) => {
                vec![0, 0, 0, 0, 0, 0, 0, 1]
            }
            Data::Bool(false) => {
                vec![0, 0, 0, 0, 0, 0, 0, 0]
            }
            Data::Number(num) => num.to_be_bytes().to_vec(),
            Data::NegativeNumber(num) => num.to_be_bytes().to_vec(),
        };
        Ok(enc)
        */
    }
}

impl TypedData {
    pub async fn from_document_and_options(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
    ) -> Result<Self, TypedDataConstructionError> {
        let doc_dataset = document
            .to_dataset_for_signing(None)
            .await
            .map_err(|e| TypedDataConstructionError::DocumentToDataset(e.to_string()))?;
        let doc_dataset_normalized = crate::urdna2015::normalize(&doc_dataset)
            .map_err(|e| TypedDataConstructionError::NormalizeDocument(e.to_string()))?;
        let sigopts_dataset = proof
            .to_dataset_for_signing(Some(document))
            .await
            .map_err(|e| TypedDataConstructionError::ProofToDataset(e.to_string()))?;
        let sigopts_dataset_normalized = crate::urdna2015::normalize(&sigopts_dataset)
            .map_err(|e| TypedDataConstructionError::NormalizeProof(e.to_string()))?;

        let types = Types {
            eip712_domain: Struct(vec![Member {
                name: "name".to_string(),
                type_: Type::String,
            }]),
            types: vec![(
                "LDPSigningRequest".to_string(),
                Struct(vec![
                    Member {
                        name: "document".to_string(),
                        type_: Type::Array(Box::new(Type::Array(Box::new(Type::String)))),
                    },
                    Member {
                        name: "proof".to_string(),
                        type_: Type::Array(Box::new(Type::Array(Box::new(Type::String)))),
                    },
                ]),
            )]
            .into_iter()
            .collect(),
        };
        use crate::rdf::Statement;
        fn encode_statement(statement: Statement) -> Data {
            let mut terms = vec![
                Data::String(String::from(&statement.subject)),
                Data::String(String::from(&statement.predicate)),
                Data::String(String::from(&statement.object)),
            ];
            if let Some(graph_label) = statement.graph_label.as_ref() {
                terms.push(Data::String(String::from(graph_label)));
            }
            Data::Array(terms)
        }

        Ok(Self {
            types,
            primary_type: "LDPSigningRequest".to_string(),
            domain: Data::Struct(
                vec![(
                    "name".to_string(),
                    Data::String("Eip712Method2021".to_string()),
                )]
                .into_iter()
                .collect(),
            ),
            message: Data::Struct(
                vec![
                    (
                        "document".to_string(),
                        Data::Array(
                            doc_dataset_normalized
                                .statements()
                                .into_iter()
                                .map(encode_statement)
                                .collect(),
                        ),
                    ),
                    (
                        "proof".to_string(),
                        Data::Array(
                            sigopts_dataset_normalized
                                .statements()
                                .into_iter()
                                .map(encode_statement)
                                .collect(),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        })
    }

    /// Encode a typed data message for hashing and signing.
    /// [Reference[(https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#specification)
    pub fn hash(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let message_struct = self
            .types
            .types
            .get(&self.primary_type)
            .ok_or(TypedDataHashError::MissingPrimaryTypeStruct)?;
        let message_hash = self
            .message
            .hash(&message_struct, &self.primary_type, &self.types)?;
        let domain_separator =
            self.domain
                .hash(&self.types.eip712_domain, "EIP712Domain", &self.types)?;
        let bytes = vec![
            vec![0x19, 0x01],
            domain_separator.to_vec(),
            message_hash.to_vec(),
        ]
        .concat();
        Ok(keccak(bytes).to_fixed_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_type() {
        let types = Types {
            eip712_domain: Struct(Vec::new()),
            types: vec![
                (
                    "Transaction".to_string(),
                    Struct(vec![
                        Member {
                            name: "from".to_string(),
                            type_: Type::Reference("Person".to_string()),
                        },
                        Member {
                            name: "to".to_string(),
                            type_: Type::Reference("Person".to_string()),
                        },
                        Member {
                            name: "tx".to_string(),
                            type_: Type::Reference("Asset".to_string()),
                        },
                    ]),
                ),
                (
                    "Person".to_string(),
                    Struct(vec![
                        Member {
                            name: "wallet".to_string(),
                            type_: Type::Address,
                        },
                        Member {
                            name: "name".to_string(),
                            type_: Type::String,
                        },
                    ]),
                ),
                (
                    "Asset".to_string(),
                    Struct(vec![
                        Member {
                            name: "token".to_string(),
                            type_: Type::Address,
                        },
                        Member {
                            name: "amount".to_string(),
                            type_: Type::UintN(256),
                        },
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let transaction_struct = types.types.get("Transaction").unwrap();
        let type_encoded = transaction_struct.encode("Transaction", &types).unwrap();
        let type_encoded_string = String::from_utf8(type_encoded).unwrap();
        assert_eq!(type_encoded_string, "Transaction(Person from,Person to,Asset tx)Asset(address token,uint256 amount)Person(address wallet,string name)");
    }

    #[test]
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#example
    // https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js
    #[ignore]
    // TODO
    fn hash_typed_data() {
        let _addr = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";
        let typed_data: TypedData = serde_json::from_value(json!({
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "Person": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "wallet",
                "type": "address"
              }
            ],
            "Mail": [
              {
                "name": "from",
                "type": "Person"
              },
              {
                "name": "to",
                "type": "Person"
              },
              {
                "name": "contents",
                "type": "string"
              }
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
        let hash = typed_data.hash().unwrap();
        let hash_hex = crate::keccak_hash::bytes_to_lowerhex(&hash);
        assert_eq!(
            hash_hex,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
        /*
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(&sig);
        assert_eq!(sig_hex, "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c");
        */
    }
}
