use ssi_dids::{
    did_resolve::{
        dereference, DIDResolver, DereferencingInputMetadata, DocumentMetadata, Metadata,
        ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    },
    Context, Contexts, DIDMethod, Document, Service, Source, VerificationMethod,
    VerificationMethodMap, DEFAULT_CONTEXT, DIDURL,
};
use ssi_jwk::{
    blakesig::hash_public_key, p256_parse, secp256k1_parse, Base64urlUInt, OctetParams, Params, JWK,
};
use ssi_jws::{decode_unverified, decode_verify};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use json_patch::patch;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap, convert::TryInto, default::Default, str::FromStr, string::ToString,
};

mod explorer;

/// did:tz DID Method
///
/// [Specification](https://github.com/spruceid/did-tezos/)
#[derive(Default, Clone)]
pub struct DIDTz {
    tzkt_url: Option<String>,
}

#[derive(Clone, Debug)]
enum Prefix {
    TZ1,
    TZ2,
    TZ3,
    KT1,
}

impl FromStr for Prefix {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tz1" => Prefix::TZ1,
            "tz2" => Prefix::TZ2,
            "tz3" => Prefix::TZ3,
            "KT1" => Prefix::KT1,
            _ => return Err(()),
        })
    }
}

impl ToString for Prefix {
    fn to_string(&self) -> String {
        match self {
            Prefix::TZ1 => "tz1",
            Prefix::TZ2 => "tz2",
            Prefix::TZ3 => "tz3",
            Prefix::KT1 => "KT1",
        }
        .to_string()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDTz {
    /// Resolve a did:tz DID.
    ///
    /// # Resolution options
    ///
    /// ## `tzkt_url`
    /// Custom indexer endpoint URL.
    ///
    /// ## `updates`
    /// [Off-Chain DID Document Updates](https://did-tezos.spruceid.com/#off-chain-did-document-updates), as specified in the Tezos DID Method Specification.
    ///
    /// ## `public_key`
    /// Public key in Base58 format ([publicKeyBase58](https://w3c-ccg.github.io/security-vocab/#publicKeyBase58)) to add to a [derived DID document (implicit resolution)](https://did-tezos.spruceid.com/#deriving-did-documents).
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (network, address) = match did.split(':').collect::<Vec<&str>>().as_slice() {
            ["did", "tz", address] if address.len() == 36 => ("mainnet", address.to_string()),
            ["did", "tz", network, address] if address.len() == 36 => {
                (*network, address.to_string())
            }
            _ => {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };
        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-26.md
        let genesis_block_hash = match network {
            "mainnet" => "NetXdQprcVkpaWU",
            "delphinet" => "NetXm8tYqnMWky1",
            "granadanet" => "NetXz969SFaFn8k",
            "edonet" => "NetXSgo1ZT2DRUG",
            "florencenet" => "NetXxkAx4woPLyu",
            _ => {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let prefix: Prefix = match address.get(0..3) {
            Some(prefix) => match Prefix::from_str(prefix) {
                Ok(p) => p,
                Err(_) => {
                    return (
                        ResolutionMetadata::from_error(ERROR_INVALID_DID),
                        None,
                        None,
                    )
                }
            },
            None => {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };
        let (_curve, proof_type, proof_type_iri) = prefix_to_curve_type(prefix.clone());

        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("blockchainAccountId".to_string()),
            ..Default::default()
        };
        let public_key = if let Some(s) = &input_metadata.property_set {
            match s.get("public_key") {
                Some(pk) => match pk {
                    Metadata::String(pks) => Some(pks.clone()),
                    _ => {
                        return (
                            ResolutionMetadata {
                                error: Some("Public key is not a string.".to_string()),
                                ..Default::default()
                            },
                            None,
                            None,
                        );
                    }
                },
                None => None,
            }
        } else {
            None
        };

        let mut doc = DIDTz::tier1_derivation(
            did,
            &vm_didurl,
            proof_type,
            proof_type_iri,
            &address,
            genesis_block_hash,
            public_key,
        );

        let default_url = match &self.tzkt_url {
            Some(u) => u.clone(),
            None => format!("https://api.{network}.tzkt.io"),
        };
        let mut tzkt_url = &default_url;
        if let Some(s) = &input_metadata.property_set {
            if let Some(url) = s.get("tzkt_url") {
                match url {
                    Metadata::String(u) => tzkt_url = u,
                    _ => {
                        return (
                            ResolutionMetadata {
                                error: Some("TzKT API URL should be a string.".to_string()),
                                ..Default::default()
                            },
                            Some(doc),
                            None,
                        )
                    }
                }
            }
        };

        if let (Some(service), Some(vm)) =
            match DIDTz::tier2_resolution(prefix.clone(), tzkt_url, did, &address).await {
                Ok(res) => res,
                Err(e) => {
                    return (
                        ResolutionMetadata {
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        None,
                    )
                }
            }
        {
            doc.service = Some(vec![service]);
            if let Some(ref mut vms) = doc.verification_method {
                vms.push(vm);
            } else {
                doc.verification_method = Some(vec![vm]);
            }
        }

        if let Some(s) = &input_metadata.property_set {
            if let Some(updates_metadata) = s.get("updates") {
                let conversion: String = match updates_metadata {
                    Metadata::String(s) => s.clone(),
                    Metadata::Map(m) => match serde_json::to_string(m) {
                        Ok(s) => s.clone(),
                        Err(e) => {
                            return (
                                ResolutionMetadata {
                                    error: Some(e.to_string()),
                                    ..Default::default()
                                },
                                Some(doc),
                                None,
                            )
                        }
                    },
                    _ => {
                        return (
                            ResolutionMetadata {
                                error: Some(
                                    "Cannot convert this type for off-chain updates.".to_string(),
                                ),
                                ..Default::default()
                            },
                            Some(doc),
                            None,
                        )
                    }
                };
                let updates: Updates = match serde_json::from_str(&conversion) {
                    Ok(uu) => uu,
                    Err(e) => {
                        return (
                            ResolutionMetadata {
                                error: Some(e.to_string()),
                                ..Default::default()
                            },
                            Some(doc),
                            None,
                        );
                    }
                };
                if let Err(e) = self.tier3_updates(prefix, &mut doc, updates).await {
                    return (
                        ResolutionMetadata {
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        None,
                    );
                }
            }
        }

        let res_meta = ResolutionMetadata {
            ..Default::default()
        };

        let doc_meta = DocumentMetadata {
            ..Default::default()
        };

        (res_meta, Some(doc), Some(doc_meta))
    }

    fn to_did_method(&self) -> Option<&dyn DIDMethod> {
        Some(self)
    }
}

// addr must be at least 4 bytes
fn prefix_to_curve_type(prefix: Prefix) -> (&'static str, &'static str, &'static str) {
    match prefix {
        Prefix::TZ1 | Prefix::KT1 => (
            "Ed25519",
            "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
            "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        ),
        Prefix::TZ2 => (
            "secp256k1",
            "EcdsaSecp256k1RecoveryMethod2020",
            "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
        ),
        Prefix::TZ3 => (
            "P-256",
            "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
            "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        ),
    }
}

fn get_public_key_from_doc(doc: &Document, auth_vm_id: &str) -> Option<String> {
    if let Some(vms) = &doc.authentication {
        for vm in vms {
            #[allow(clippy::single_match)]
            match vm {
                VerificationMethod::Map(vmm) => {
                    if vmm.id == auth_vm_id {
                        return vmm.public_key_base58.clone();
                    }
                }
                // TODO, derefencing
                _ => {}
            }
        }
        None
    } else {
        None
    }
}

impl DIDMethod for DIDTz {
    fn name(&self) -> &'static str {
        "tz"
    }

    // TODO need to handle different networks
    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            Source::KeyAndPattern(jwk, pattern) => {
                if !pattern.is_empty() {
                    // TODO: support pattern
                    return None;
                }
                jwk
            }
            _ => return None,
        };
        let hash = match hash_public_key(jwk) {
            Ok(hash) => hash,
            _ => return None,
        };
        let did = "did:tz:".to_string() + &hash;
        Some(did)
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SignedIetfJsonPatchPayload {
    ietf_json_patch: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type", content = "value")]
enum Updates {
    SignedIetfJsonPatch(Vec<String>),
}

impl DIDTz {
    fn tier1_derivation(
        did: &str,
        vm_didurl: &DIDURL,
        proof_type: &str,
        proof_type_iri: &str,
        address: &str,
        genesis_block_hash: &str,
        public_key: Option<String>,
    ) -> Document {
        let mut context = BTreeMap::new();
        context.insert(
            "blockchainAccountId".to_string(),
            Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
        );
        context.insert(
            proof_type.to_string(),
            Value::String(proof_type_iri.to_string()),
        );
        if public_key.is_some() {
            context.insert(
                "publicKeyBase58".to_string(),
                Value::String("https://w3id.org/security#publicKeyBase58".to_string()),
            );
        }
        Document {
            context: Contexts::Many(vec![
                Context::URI(DEFAULT_CONTEXT.into()),
                Context::Object(context),
            ]),
            id: did.to_string(),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: String::from(vm_didurl.clone()),
                type_: proof_type.to_string(),
                controller: did.to_string(),
                blockchain_account_id: Some(format!("tezos:{genesis_block_hash}:{address}")),
                ..Default::default()
            })]),
            authentication: match public_key {
                Some(_) => Some(vec![VerificationMethod::Map(VerificationMethodMap {
                    id: vm_didurl.to_string(),
                    controller: did.to_string(),
                    public_key_base58: public_key,
                    type_: proof_type.to_string(),
                    ..Default::default()
                })]),
                None => Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            },
            ..Default::default()
        }
    }

    async fn tier2_resolution(
        prefix: Prefix,
        tzkt_url: &str,
        did: &str,
        address: &str,
    ) -> Result<(Option<Service>, Option<VerificationMethod>)> {
        if let Some(did_manager) = match prefix {
            Prefix::KT1 => Some(address.to_string()),
            _ => explorer::retrieve_did_manager(tzkt_url, address).await?,
        } {
            Ok((
                Some(explorer::execute_service_view(tzkt_url, did, &did_manager).await?),
                Some(explorer::execute_auth_view(tzkt_url, &did_manager).await?),
            ))
        } else {
            Ok((None, None))
        }
    }

    async fn tier3_updates(
        &self,
        prefix: Prefix,
        doc: &mut Document,
        updates: Updates,
    ) -> Result<()> {
        match updates {
            Updates::SignedIetfJsonPatch(patches) => {
                for jws in patches {
                    let mut doc_json = serde_json::to_value(&mut *doc)?;
                    let (patch_metadata, _) = decode_unverified(&jws)?;
                    let curve = prefix_to_curve_type(prefix.clone()).0.to_string();
                    let kid = match patch_metadata.key_id {
                        Some(k) => k,
                        None => return Err(anyhow!("No kid in JWS JSON patch.")),
                    };
                    let kid_didurl: DIDURL = kid.clone().try_into()?;
                    // TODO need to compare address + network instead of the String
                    // did:tz:tz1blahblah == did:tz:mainnet:tz1blahblah
                    let kid_doc = if kid_didurl.did == doc.id {
                        doc.clone()
                    } else {
                        let (deref_meta, deref_content, _) =
                            dereference(self, &kid, &DereferencingInputMetadata::default()).await;
                        if let Some(e) = deref_meta.error {
                            return Err(anyhow!("Error dereferencing kid: {}", e));
                        } else {
                            match deref_content {
                                ssi_dids::did_resolve::Content::DIDDocument(d) => d,
                                _ => {
                                    return Err(anyhow!("Dereferenced content not a DID document."))
                                }
                            }
                        }
                    };
                    if let Some(public_key) = get_public_key_from_doc(&kid_doc, &kid) {
                        let jwk = match prefix {
                            Prefix::TZ1 | Prefix::KT1 => {
                                let pk = bs58::decode(public_key)
                                    .with_check(None)
                                    .into_vec()
                                    .map_err(|e| anyhow!("Couldn't decode public key: {}", e))?
                                    [4..]
                                    .to_vec();
                                JWK {
                                    params: Params::OKP(OctetParams {
                                        curve,
                                        public_key: Base64urlUInt(pk),
                                        private_key: None,
                                    }),
                                    public_key_use: None,
                                    key_operations: None,
                                    algorithm: None,
                                    key_id: None,
                                    x509_url: None,
                                    x509_thumbprint_sha1: None,
                                    x509_certificate_chain: None,
                                    x509_thumbprint_sha256: None,
                                }
                            }
                            Prefix::TZ2 => {
                                let pk = bs58::decode(public_key)
                                    .with_check(None)
                                    .into_vec()
                                    .map_err(|e| anyhow!("Couldn't decode public key: {}", e))?
                                    [4..]
                                    .to_vec();
                                secp256k1_parse(&pk).map_err(|e| {
                                    anyhow!("Couldn't create JWK from secp256k1 public key: {}", e)
                                })?
                            }
                            Prefix::TZ3 => {
                                let pk = bs58::decode(public_key)
                                    .with_check(None)
                                    .into_vec()
                                    .map_err(|e| anyhow!("Couldn't decode public key: {}", e))?
                                    [4..]
                                    .to_vec();
                                p256_parse(&pk).map_err(|e| {
                                    anyhow!("Couldn't create JWK from P-256 public key: {}", e)
                                })?
                            }
                            #[allow(unreachable_patterns)]
                            p => return Err(anyhow!("{} support not enabled.", p.to_string())),
                        };
                        let (_, patch_) = decode_verify(&jws, &jwk)?;
                        patch(
                            &mut doc_json,
                            &serde_json::from_slice(
                                serde_json::from_slice::<SignedIetfJsonPatchPayload>(&patch_)?
                                    .ietf_json_patch
                                    .to_string()
                                    .as_bytes(),
                            )?,
                        )?;
                        *doc = serde_json::from_value(doc_json)?;
                    } else {
                        return Err(anyhow!("Need public key for signed patches"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_core::one_or_many::OneOrMany;
    use ssi_dids::did_resolve::ResolutionInputMetadata;
    use ssi_dids::ServiceEndpoint;
    use ssi_jws::encode_sign;
    use ssi_ldp::{ProofSuite, ProofSuiteType};
    use std::collections::BTreeMap as Map;

    const TZ1: &str = "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";
    const TZ1_JSON: &str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

    const LIVE_TZ1: &str = "tz1giDGsifWB9q9siekCKQaJKrmC9da5M43J";
    const LIVE_KT1: &str = "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi";
    const LIVE_NETWORK: &str = "NetXdQprcVkpaWU";
    const JSON_PATCH: &str = r#"{"ietf-json-patch": [
                                    {
                                        "op": "add",
                                        "path": "/service/1",
                                        "value": {
                                            "id": "test_service_id",
                                            "type": "test_service",
                                            "serviceEndpoint": "test_service_endpoint"
                                        }
                                    }
                                ]}"#;

    const DIDTZ: DIDTz = DIDTz { tzkt_url: None };

    #[test]
    fn jwk_to_did_tezos() {
        // TODO: add tz2 and tz3 test cases
        let jwk: JWK = serde_json::from_str(TZ1_JSON).unwrap();
        let tz1 = DIDTZ.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(tz1, TZ1);
    }

    #[test]
    fn jwk_to_tz3() {
        let jwk: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4",
            "y": "OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"
        }))
        .unwrap();
        let did = DIDTZ.generate(&Source::Key(&jwk)).unwrap();
        // https://github.com/murbard/pytezos/blob/a228a67fbc94b11dd7dbc7ff0df9e996d0ff5f01tests/test_crypto.py#L34
        assert_eq!(did, "did:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX");
    }

    #[tokio::test]
    async fn test_glyph_split() {
        // Subslicing this method-specific id by byte range 0..3 would break a char boundary.
        // https://doc.rust-lang.org/std/ops/struct.Range.html#impl-SliceIndex%3Cstr%3E
        let bad_did = "did:tz:💣️00000000000000000000000000000";
        let (res_meta, _doc_opt, _meta_opt) = DIDTZ
            .resolve(bad_did, &ResolutionInputMetadata::default())
            .await;
        assert_ne!(res_meta.error, None);
    }

    #[tokio::test]
    async fn test_derivation_tz1() {
        let (res_meta, doc_opt, _meta_opt) = DIDTZ
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
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
                }
              ],
              "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"
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
    async fn test_derivation_tz2() {
        let (res_meta, doc_opt, _meta_opt) = DIDTZ
            .resolve(
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
                }
              ],
              "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"
              }],
              "authentication": [
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
              ],
              "assertionMethod": [
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
              ]
            })
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_tz1() {
        use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("v1/contracts"))
            .and(query_param(
                "creator",
                "tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
            ))
            .and(query_param("codeHash", "1222545108"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi"])),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
          .and(path(&format!("v1/contracts/{}/storage", "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi")))
          .respond_with(
            ResponseTemplate::new(200)
            .set_body_json(json!({"verification_method": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId",
              "service": {"type_": "TezosDiscoveryService", "endpoint": "http://example.com"}})),
            )
          .mount(&mock_server)
          .await;

        let didtz = DIDTz {
            tzkt_url: Some(mock_server.uri()),
        };

        let vc_str = r###"{
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
            "issuanceDate": "2021-01-27T16:39:07Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        // let public_key =
        //     PublicKey::from_base58check("edpkthtzpq4e8AhtjZ6BPK63iLfqpH7rzjDVbjxjbTuv3kMoGQi26A")
        //         .unwrap();
        // let private_key =
        //     PrivateKey::from_base58check("")
        //         .unwrap();
        // let key = JWK {
        //     params: ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
        //         curve: "Ed25519".to_string(),
        //         public_key: ssi_jwk::Base64urlUInt(public_key.as_ref()[..].into()),
        //         private_key: Some(ssi_jwk::Base64urlUInt(private_key.as_ref()[..].into())),
        //     }),
        //     public_key_use: None,
        //     key_operations: None,
        //     algorithm: None,
        //     key_id: None,
        //     x509_url: None,
        //     x509_certificate_chain: None,
        //     x509_thumbprint_sha1: None,
        //     x509_thumbprint_sha256: None,
        // };
        let did = "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq".to_string();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(did.to_string() + "#blockchainAccountId")),
            ..Default::default()
        };
        eprintln!("vm {:?}", issue_options.verification_method);
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vc_no_proof = vc.clone();
        // let proof = vc.generate_proof(&key, &issue_options, &DIDTZ).await.unwrap();
        let proof_str = r###"
{
  "@context": {
    "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021": {
      "@context": {
        "@protected": true,
        "@version": 1.1,
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
        "id": "@id",
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@context": {
            "@protected": true,
            "@version": 1.1,
            "assertionMethod": {
              "@container": "@set",
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id"
            },
            "authentication": {
              "@container": "@set",
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id"
            },
            "id": "@id",
            "type": "@type"
          },
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab"
        },
        "publicKeyJwk": {
          "@id": "https://w3id.org/security#publicKeyJwk",
          "@type": "@json"
        },
        "type": "@type",
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      },
      "@id": "https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021"
    }
  },
  "type": "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021",
  "proofPurpose": "assertionMethod",
  "verificationMethod": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId",
  "created": "2021-03-02T18:59:44.462Z",
  "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..thpumbPTltH6b6P9QUydy8DcoK2Jj63-FIntxiq09XBk7guF_inA0iQWw7_B_GBwmmsmhYdGL4TdtiNieAdeAg",
  "publicKeyJwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"
  }
}"###;
        let proof = serde_json::from_str(proof_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &didtz, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(!vc_bad_issuer
            .verify(None, &didtz, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let other_key = JWK::generate_ed25519().unwrap();
        let proof_bad = ProofSuiteType::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
            .sign(
                &vc_no_proof,
                &issue_options,
                &didtz,
                &mut context_loader,
                &other_key,
                None,
            )
            .await
            .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(!vc_wrong_key
            .verify(None, &didtz, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Make it into a VP
        use ssi_core::one_or_many::OneOrMany;
        use ssi_vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            context: ssi_vc::Contexts::Many(vec![ssi_vc::Context::URI(ssi_vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
            holder_binding: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method =
            Some(URI::String(did.to_string() + "#blockchainAccountId"));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        // let vp_proof = vp.generate_proof(&key, &vp_issue_options, &DIDTZ).await.unwrap();
        let vp_proof_str = r###"
{
  "@context": {
    "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021": {
      "@context": {
        "@protected": true,
        "@version": 1.1,
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
        "id": "@id",
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@context": {
            "@protected": true,
            "@version": 1.1,
            "assertionMethod": {
              "@container": "@set",
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id"
            },
            "authentication": {
              "@container": "@set",
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id"
            },
            "id": "@id",
            "type": "@type"
          },
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab"
        },
        "publicKeyJwk": {
          "@id": "https://w3id.org/security#publicKeyJwk",
          "@type": "@json"
        },
        "type": "@type",
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      },
      "@id": "https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021"
    }
  },
  "type": "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021",
  "proofPurpose": "authentication",
  "verificationMethod": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId",
  "created": "2021-03-02T19:05:08.271Z",
  "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..7GLIUeNKvO3WsA3DmBZpbuPinhOcv7Mhgx9QP0svO55T_Zoy7wmJJtLXSoghtkI7DWOnVbiJO5X246Qr0CqGDw",
  "publicKeyJwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"
  }
}"###;
        let vp_proof = serde_json::from_str(vp_proof_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&vp_proof).unwrap());
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp
            .verify(Some(vp_issue_options.clone()), &didtz, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1
            .verify(Some(vp_issue_options), &didtz, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(!vp_verification_result.errors.is_empty());

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(!vp2
            .verify(None, &didtz, &mut context_loader)
            .await
            .errors
            .is_empty());
    }

    #[tokio::test]
    async fn credential_prove_verify_did_tz2() {
        use ssi_jwk::Algorithm;
        use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let mut key = JWK::generate_secp256k1().unwrap();
        // mark this key as being for use with key recovery
        key.algorithm = Some(Algorithm::ES256KR);
        let did = DIDTZ.generate(&Source::Key(&key)).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "issuer": did.clone(),
            "issuanceDate": "2021-02-18T20:23:13Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(did.to_string() + "#blockchainAccountId")),
            ..Default::default()
        };
        eprintln!("vm {:?}", issue_options.verification_method);
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vc_no_proof = vc.clone();
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDTZ, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDTZ, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(!vc_bad_issuer
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let other_key = JWK::generate_ed25519().unwrap();
        let proof_bad = ProofSuiteType::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
            .sign(
                &vc_no_proof,
                &issue_options,
                &DIDTZ,
                &mut context_loader,
                &other_key,
                None,
            )
            .await
            .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(!vc_wrong_key
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Make it into a VP
        use ssi_core::one_or_many::OneOrMany;
        use ssi_vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            context: ssi_vc::Contexts::Many(vec![ssi_vc::Context::URI(ssi_vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
            holder_binding: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method =
            Some(URI::String(did.to_string() + "#blockchainAccountId"));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vp_proof = vp
            .generate_proof(&key, &vp_issue_options, &DIDTZ, &mut context_loader)
            .await
            .unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp
            .verify(Some(vp_issue_options.clone()), &DIDTZ, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1
            .verify(Some(vp_issue_options), &DIDTZ, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(!vp_verification_result.errors.is_empty());

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(!vp2
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());
    }

    #[tokio::test]
    async fn test_derivation_tz3() {
        let (res_meta, doc_opt, _meta_opt) = DIDTZ
            .resolve(
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
                }
              ],
              "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId",
                "type": "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"
              }],
              "authentication": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
              ],
              "assertionMethod": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
              ]
            })
        );
    }

    #[tokio::test]
    async fn test_json_patch_tz1() {
        let address = "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb";
        let pk = "edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn";
        let sk = "edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "id": did,
          "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
            "controller": did,
            "blockchainAccountId": format!("tezos:sandbox:{}", address),
            "publicKeyBase58": pk
          }],
          "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
          }]
        }))
        .unwrap();
        let key = JWK {
            key_id: Some(format!("{}#blockchainAccountId", did)),
            ..ssi_tzkey::jwk_from_tezos_key(sk).unwrap()
        };
        let jws = encode_sign(ssi_jwk::Algorithm::EdDSA, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ1, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[1],
            Service {
                id: "test_service_id".to_string(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "test_service_endpoint".to_string()
                ))),
                property_set: Some(Map::new()) // TODO should be None
            }
        );
    }

    #[tokio::test]
    async fn test_json_patch_tz2() {
        let address = "tz2RZoj9oqoA8bDeUoAKLjf8nLPQKmYjaj6Q";
        let pk = "sppk7bRNbJ2n9PNQo295UJiYQ8iMma8ysRH9mCRFB14yhzLCwdGay9y";
        let sk = "spsk1Uc5MDutpZmwPVeSLL2BbtCAqfrG8zbMs6dwoaeXX8kw35S474";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "id": did,
          "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": did,
            "blockchainAccountId": format!("tezos:sandbox:{}", address),
            "publicKeyBase58": pk
          }],
          "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
          }]
        }))
        .unwrap();
        // let public_key = pk.from_base58check().unwrap()[4..].to_vec();
        let private_key = bs58::decode(&sk).with_check(None).into_vec().unwrap()[4..].to_owned();
        use ssi_jwk::ECParams;
        let key = JWK {
            params: ssi_jwk::Params::EC(ECParams {
                curve: Some("secp256k1".to_string()),
                x_coordinate: None,
                y_coordinate: None,
                ecc_private_key: Some(Base64urlUInt(private_key)),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: Some(format!("{}#blockchainAccountId", did)),
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi_jwk::Algorithm::ES256KR, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ2, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[1],
            Service {
                id: "test_service_id".to_string(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "test_service_endpoint".to_string()
                ))),
                property_set: Some(Map::new()) // TODO should be None
            }
        );
    }

    #[tokio::test]
    async fn test_json_patch_tz3() {
        let address = "tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX";
        let pk = "p2pk679D18uQNkdjpRxuBXL5CqcDKTKzsiXVtc9oCUT6xb82zQmgUks";
        let sk = "p2sk3PM77YMR99AvD3fSSxeLChMdiQ6kkEzqoPuSwQqhPsh29irGLC";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "id": did,
          "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "blockchainAccountId": format!("tezos:sandbox:{}", address),
            "publicKeyBase58": pk
          }],
          "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
          }]
        }))
        .unwrap();
        // let public_key = pk.from_base58check().unwrap()[4..].to_vec();
        let private_key = bs58::decode(&sk).with_check(None).into_vec().unwrap()[4..].to_owned();
        let key = JWK {
            params: ssi_jwk::Params::EC(ssi_jwk::ECParams {
                curve: Some("P-256".to_string()),
                x_coordinate: None,
                y_coordinate: None,
                ecc_private_key: Some(Base64urlUInt(private_key)),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: Some(format!("{}#blockchainAccountId", did)),
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi_jwk::Algorithm::ES256, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ3, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[1],
            Service {
                id: "test_service_id".to_string(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "test_service_endpoint".to_string()
                ))),
                property_set: Some(Map::new()) // TODO should be None
            }
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_full_resolution() {
        // let address = "tz1giDGsifWB9q9siekCKQaJKrmC9da5M43J";
        // let pk = "edpkvRWhuk5cLe5vwR7TGfSJxVLmVDk5og45WAhsAAvfqQXmYKNPve";
        // let sk = "";
        // let did = format!("did:tz:{}", address);
        // // let public_key = bs58::decode(&pk).with_check(None).into_vec().unwrap()[4..].to_owned();
        // // let private_key = bs58::decode(&sk).with_check(None).into_vec().unwrap()[4..].to_owned();
        // // println!("LEN: {}", private_key.len());
        // // let key = JWK {
        // //     params: ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
        // //         curve: "Ed25519".to_string(),
        // //         public_key: ssi_jwk::Base64urlUInt(public_key),
        // //         private_key: Some(ssi_jwk::Base64urlUInt(private_key)),
        // //     }),
        // //     public_key_use: None,
        // //     key_operations: None,
        // //     algorithm: None,
        // //     key_id: Some(format!("{}#blockchainAccountId", did)),
        // //     x509_url: None,
        // //     x509_certificate_chain: None,
        // //     x509_thumbprint_sha1: None,
        // //     x509_thumbprint_sha256: None,
        // // };
        // let key = JWK {
        //     key_id: Some(format!("{}#blockchainAccountId", did)),
        //     ..ssi_tzkey::jwk_from_tezos_key(sk).unwrap()
        // };
        // let jws = encode_sign(ssi_jwk::Algorithm::EdDSA, JSON_PATCH, &key).unwrap();
        // println!("{}", jws);
        // assert!(false);
        let jws = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp0ejp0ejFnaURHc2lmV0I5cTlzaWVrQ0tRYUpLcm1DOWRhNU00M0ojYmxvY2tjaGFpbkFjY291bnRJZCJ9.eyJpZXRmLWpzb24tcGF0Y2giOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJvcCI6ICJhZGQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInBhdGgiOiAiL3NlcnZpY2UvMSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImlkIjogInRlc3Rfc2VydmljZV9pZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInR5cGUiOiAidGVzdF9zZXJ2aWNlIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAic2VydmljZUVuZHBvaW50IjogInRlc3Rfc2VydmljZV9lbmRwb2ludCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF19.HqPI6jFXuEMZ-fQfSE9MstDlKifoqdt8sAtUJ8I3IYwMybLxrabl35hTXyf5Uj6XwnYKrKbBvXImt52WQla5CQ".to_string();
        let input_metadata: ResolutionInputMetadata = serde_json::from_value(
            json!({"updates": {"type": "signed-ietf-json-patch", "value": [jws]},
                   "public_key": "edpkvRWhuk5cLe5vwR7TGfSJxVLmVDk5og45WAhsAAvfqQXmYKNPve"}),
        )
        .unwrap();
        let live_did = format!("did:tz:{}", LIVE_TZ1);
        let (res_meta, res_doc, _res_doc_meta) = DIDTZ.resolve(&live_did, &input_metadata).await;
        assert_eq!(res_meta.error, None);
        let d = res_doc.unwrap();
        let expected = Document {
            id: live_did.clone(),
            verification_method: Some(vec![
                VerificationMethod::Map(VerificationMethodMap {
                    id: format!("{}#blockchainAccountId", live_did),
                    type_: "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021".to_string(),
                    blockchain_account_id: Some(format!("tezos:{}:{}", LIVE_NETWORK, LIVE_TZ1)),
                    controller: live_did.clone(),
                    property_set: Some(Map::new()), // TODO should be None
                    ..Default::default()
                }),
                VerificationMethod::DIDURL(DIDURL {
                    did: format!("did:pkh:tz:{}", LIVE_TZ1),
                    path_abempty: "".to_string(),
                    query: None,
                    fragment: Some("TezosMethod2021".to_string()),
                }),
            ]),
            service: Some(vec![
                Service {
                    id: format!("{}#discovery", live_did),
                    type_: OneOrMany::One("TezosDiscoveryService".to_string()),
                    service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                        "http://example.com".to_string(),
                    ))),
                    property_set: Some(Map::new()), // TODO should be None
                },
                Service {
                    id: "test_service_id".to_string(),
                    type_: OneOrMany::One("test_service".to_string()),
                    service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                        "test_service_endpoint".to_string(),
                    ))),
                    property_set: Some(Map::new()),
                },
            ]),
            ..Default::default()
        };
        assert_eq!(d.id, expected.id);
        assert_eq!(d.controller, expected.controller);
        assert_eq!(d.verification_method, expected.verification_method);
        assert_eq!(d.service, expected.service);
        // assert_eq!(d, expected);
    }

    #[tokio::test]
    #[ignore]
    async fn test_full_resolution_kt1() {
        let live_did_manager = format!("did:tz:{}", LIVE_KT1);

        let (res_meta, res_doc, _res_doc_meta) = DIDTZ
            .resolve(&live_did_manager, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        let d = res_doc.unwrap();
        let expected = Document {
            id: live_did_manager.clone(),
            verification_method: Some(vec![
                VerificationMethod::Map(VerificationMethodMap {
                    id: format!("{}#blockchainAccountId", live_did_manager),
                    type_: "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021".to_string(),
                    blockchain_account_id: Some(format!("tezos:{}:{}", LIVE_NETWORK, LIVE_KT1)),
                    controller: live_did_manager.clone(),
                    property_set: None,
                    ..Default::default()
                }),
                VerificationMethod::DIDURL(DIDURL {
                    did: format!("did:pkh:tz:{}", LIVE_TZ1),
                    path_abempty: "".to_string(),
                    query: None,
                    fragment: Some("TezosMethod2021".to_string()),
                }),
            ]),
            service: Some(vec![Service {
                id: format!("{}#discovery", live_did_manager),
                type_: OneOrMany::One("TezosDiscoveryService".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "http://example.com".to_string(),
                ))),
                property_set: None,
            }]),
            ..Default::default()
        };
        assert_eq!(d.id, expected.id);
        assert_eq!(d.controller, expected.controller);
        assert_eq!(d.verification_method, expected.verification_method);
        assert_eq!(d.service, expected.service);
    }

    #[tokio::test]
    async fn credential_prove_verify_did_tz3() {
        use ssi_jwk::Algorithm;
        use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let mut key = JWK::generate_p256().unwrap();
        key.algorithm = Some(Algorithm::ESBlake2b);
        let did = DIDTZ.generate(&Source::Key(&key)).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "issuer": did.clone(),
            "issuanceDate": "2021-03-04T14:18:21Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(did.to_string() + "#blockchainAccountId")),
            ..Default::default()
        };
        eprintln!("vm {:?}", issue_options.verification_method);
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vc_no_proof = vc.clone();
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDTZ, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDTZ, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(!vc_bad_issuer
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let other_key = JWK::generate_p256().unwrap();
        let proof_bad = ProofSuiteType::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
            .sign(
                &vc_no_proof,
                &issue_options,
                &DIDTZ,
                &mut context_loader,
                &other_key,
                None,
            )
            .await
            .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(!vc_wrong_key
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Make it into a VP
        use ssi_core::one_or_many::OneOrMany;
        use ssi_vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            context: ssi_vc::Contexts::Many(vec![ssi_vc::Context::URI(ssi_vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
            holder_binding: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method =
            Some(URI::String(did.to_string() + "#blockchainAccountId"));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
        let vp_proof = vp
            .generate_proof(&key, &vp_issue_options, &DIDTZ, &mut context_loader)
            .await
            .unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp
            .verify(Some(vp_issue_options.clone()), &DIDTZ, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1
            .verify(Some(vp_issue_options), &DIDTZ, &mut context_loader)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(!vp_verification_result.errors.is_empty());

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(!vp2
            .verify(None, &DIDTZ, &mut context_loader)
            .await
            .errors
            .is_empty());
    }
}
