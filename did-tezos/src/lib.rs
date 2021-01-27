use ssi::did::{
    Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};
// use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};
use ssi::jwk::Params;

use async_trait::async_trait;
use chrono::prelude::*;
use serde_json;
use std::collections::HashMap;

const TZ1_EDPK: [u8; 4] = [0x65, 0x64, 0x70, 0x6b];
const TZ2_SPPK: [u8; 4] = [0x73, 0x70, 0x70, 0x6b];
const TZ3_P2PK: [u8; 4] = [0x70, 0x32, 0x70, 0x6b];

const TZ1_HASH: [u8; 3] = [0x06, 0xa1, 0x9f];
const TZ2_HASH: [u8; 3] = [0x06, 0xa1, 0xa1];
const TZ3_HASH: [u8; 3] = [0x06, 0xa1, 0xa4];

/// did:tz DID Method
///
/// [Specification](https://github.com/spruceid/did-tezos/)
pub struct DIDTz;

#[async_trait]
impl DIDResolver for DIDTz {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (network, address) = match did.split(':').collect::<Vec<&str>>().as_slice() {
            ["did", "tz", address] if address.len() == 36 => {
                ("mainnet".to_string(), address.to_string())
            }
            ["did", "tz", network, address] if address.len() == 36 => {
                (network.to_string(), address.to_string())
            }
            _ => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let (_curve, proof_type) = match prefix_to_curve_type(&address[0..3]) {
            Some(addr) => addr,
            None => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let mut property_set = HashMap::new();
        property_set.insert(
            "blockchainAccountId".to_string(),
            serde_json::Value::String(format!("{}@tezos:{}", address.to_string(), network)),
        );
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("blockchainAccountId".to_string()),
            ..Default::default()
        };

        let doc = Document {
            context: Contexts::One(DEFAULT_CONTEXT.to_string()),
            id: did.to_string(),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: String::from(vm_didurl),
                type_: proof_type.to_string(),
                controller: did.to_string(),
                property_set: Some(property_set),
                ..Default::default()
            })]),
            ..Default::default()
        };

        let res_meta = ResolutionMetadata {
            error: None,
            content_type: Some(TYPE_DID_LD_JSON.to_string()),
            property_set: None,
        };

        let doc_meta = DocumentMetadata {
            created: Some(Utc::now()),
            updated: None,
            property_set: None,
        };

        (res_meta, Some(doc), Some(doc_meta))
    }
}

fn curve_to_prefixes(curve: &str) -> Option<(&'static [u8; 4], &'static [u8; 3])> {
    let prefix = match curve {
        "Ed25519" => (&TZ1_EDPK, &TZ1_HASH),
        "secp256k1" => (&TZ2_SPPK, &TZ2_HASH),
        "P-256" => (&TZ3_P2PK, &TZ3_HASH),
        _ => return None,
    };
    Some(prefix)
}

// addr must be at least 4 bytes
fn prefix_to_curve_type(prefix: &str) -> Option<(&'static str, &'static str)> {
    let curve_type = match prefix {
        "tz1" => (
            "Ed25519",
            "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2020",
        ),
        // "tz2" => ("secp256k1", "TODO"),
        // "tz3" => ("P-256", "TODO"),
        _ => return None,
    };
    Some(curve_type)
}

impl DIDMethod for DIDTz {
    fn name(&self) -> &'static str {
        return "tz";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            _ => return None,
        };
        let params = match jwk.params {
            Params::OKP(ref okp_params) => okp_params,
            _ => return None,
        };
        let (inner_prefix, outer_prefix) = curve_to_prefixes(&params.curve)?;
        let encoded = bs58::encode(&params.public_key.0);
        let pk_b58_vec = encoded.into_vec();
        let mut inner = Vec::with_capacity(4 + pk_b58_vec.len());
        inner.extend_from_slice(inner_prefix);
        inner.extend(pk_b58_vec);
        let mut hasher = blake2b_simd::Params::new();
        hasher.hash_length(20);
        let blake2b = hasher.hash(&inner);
        let blake2b = blake2b.as_bytes();
        let mut outer = Vec::with_capacity(23);
        outer.extend_from_slice(outer_prefix);
        outer.extend_from_slice(&blake2b);
        let encoded = bs58::encode(&outer).with_check().into_string();
        let did = "did:tz:".to_string() + &encoded;
        Some(did)
    }

    fn to_resolver(&self) -> &(dyn DIDResolver + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi::did_resolve::ResolutionInputMetadata;
    use ssi::jwk::JWK;

    const TZ1: &'static str = "did:tz:tz1VFda3KmzRecjsYptDq5bJh1M1NyAqgBJf";
    const TZ1_JSON: &'static str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

    #[test]
    fn jwk_to_did_tezos() {
        // TODO: add tz2 and tz3 test cases
        let jwk: JWK = serde_json::from_str(&TZ1_JSON).unwrap();
        let tz1 = DIDTz.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(tz1, TZ1);
    }

    #[tokio::test]
    async fn test_derivation() {
        let (res_meta, doc_opt, _meta_opt) = DIDTz
            .resolve(
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2020",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8@tezos:mainnet"
              }],
              "authentication": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
              ],
              "assertionMethod": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
              ]
            })
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_tz() {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};
        let vc_str = r###"{
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              {
                "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021": {
                  "@id": "https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021",
                  "@context": {
                    "@version": 1.1,
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "challenge": "https://w3id.org/security#challenge",
                    "created": {
                      "@id": "http://purl.org/dc/terms/created",
                      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                    },
                    "domain": "https://w3id.org/security#domain",
                    "expires": {
                      "@id": "https://w3id.org/security#expiration",
                      "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                    },
                    "nonce": "https://w3id.org/security#nonce",
                    "proofPurpose": {
                      "@id": "https://w3id.org/security#proofPurpose",
                      "@type": "@vocab",
                      "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "assertionMethod": {
                          "@id": "https://w3id.org/security#assertionMethod",
                          "@type": "@id",
                          "@container": "@set"
                        },
                        "authentication": {
                          "@id": "https://w3id.org/security#authenticationMethod",
                          "@type": "@id",
                          "@container": "@set"
                        }
                      }
                    },
                    "proofValue": {
                      "@id": "https://w3id.org/security#proofValue",
                      "@type": "https://w3id.org/security#multibase"
                    },
                    "verificationMethod": {
                      "@id": "https://w3id.org/security#verificationMethod",
                      "@type": "@id"
                    },
                    "publicKeyJwk": {
                      "@id": "https://w3id.org/security#publicKeyJwk",
                      "@type": "@json"
                    }
                  }
                }
              }
            ],
            "type": ["VerifiableCredential"],
            "issuer": "did:tz:tz1iY7Am8EqrewptzQXYRZDPKvYnFLzWRgBK",
            "issuanceDate": "2021-01-27T16:39:07Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();
        let key_str = include_str!("../../tests/ed25519-2020-10-18.json");
        let key: JWK = serde_json::from_str(key_str).unwrap();
        let did = DIDTz.generate(&Source::Key(&key)).unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(did.to_string() + "#blockchainAccountId");
        eprintln!("vm {:?}", issue_options.verification_method);
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDTz).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        vc.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc.verify(None, &DIDTz).await.errors.len() > 0);
    }
}
