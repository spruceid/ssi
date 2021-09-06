use async_trait::async_trait;
use chrono::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;

use ssi::caip10::BlockchainAccountId;
use ssi::did::{
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
};
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-4.md
const CHAIN_ID_BITCOIN_MAINNET: &str = "bip122:000000000019d6689c085ae165831e93";
const CHAIN_ID_DOGECOIN_MAINNET: &str = "bip122:1a91e3dace36e2be3bf030a65679fe82";

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-26.md
const CHAIN_ID_TEZOS_MAINNET: &str = "tezos:NetXdQprcVkpaWU";

/// did:pkh DID Method
pub struct DIDPKH;

type ResolutionResult = (
    ResolutionMetadata,
    Option<Document>,
    Option<DocumentMetadata>,
);

fn resolution_result(doc: Document) -> ResolutionResult {
    let res_meta = ResolutionMetadata {
        ..Default::default()
    };
    let doc_meta = DocumentMetadata {
        ..Default::default()
    };
    (res_meta, Some(doc), Some(doc_meta))
}

fn resolution_error(err: &str) -> ResolutionResult {
    (ResolutionMetadata::from_error(err), None, None)
}

async fn resolve_tz(did: &str, account_address: String) -> ResolutionResult {
    if account_address.len() < 3 {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let (vm_type, vm_type_iri) = match &account_address[0..3] {
        "tz1" => ("Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021", "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"),
        "tz2" => ("EcdsaSecp256k1RecoveryMethod2020", "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
        "tz3" => ("P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021", "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"),
        _ => return resolution_error(&ERROR_INVALID_DID),
    };
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: CHAIN_ID_TEZOS_MAINNET.to_string(),
    };
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(vm_type.to_string(), Value::String(vm_type_iri.to_string()));
    context.insert(
        "TezosMethod2021".to_string(),
        Value::String("https://w3id.org/security#TezosMethod2021".to_string()),
    );

    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("blockchainAccountId".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: String::from(vm_url.clone()),
        type_: vm_type.to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });

    let vm2_url = DIDURL {
        did: did.to_string(),
        fragment: Some("TezosMethod2021".to_string()),
        ..Default::default()
    };
    let vm2 = VerificationMethod::Map(VerificationMethodMap {
        id: String::from(vm2_url.clone()),
        type_: "TezosMethod2021".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });

    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm, vm2]),
        authentication: Some(vec![
            VerificationMethod::DIDURL(vm_url.clone()),
            VerificationMethod::DIDURL(vm2_url.clone()),
        ]),
        assertion_method: Some(vec![
            VerificationMethod::DIDURL(vm_url),
            VerificationMethod::DIDURL(vm2_url),
        ]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_eth(did: &str, account_address: String) -> ResolutionResult {
    if !account_address.starts_with("0x") {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        Value::String("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020".to_string()),
    );
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: "eip155:1".to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("Recovery2020".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    /*
    let eip712vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("Eip712Method2021".to_string()),
        ..Default::default()
    };
    let eip712vm = VerificationMethod::Map(VerificationMethodMap {
        id: eip712vm_url.to_string(),
        type_: "Eip712Method2021".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    */
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm /*, eip712vm*/]),
        authentication: Some(vec![
            VerificationMethod::DIDURL(vm_url.clone()),
            /*
            VerificationMethod::DIDURL(eip712vm_url.clone()),
            */
        ]),
        assertion_method: Some(vec![
            VerificationMethod::DIDURL(vm_url),
            /*
            VerificationMethod::DIDURL(eip712vm_url),
            */
        ]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_celo(did: &str, account_address: String) -> ResolutionResult {
    if !account_address.starts_with("0x") {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        Value::String("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020".to_string()),
    );
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: "eip155:42220".to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("Recovery2020".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm]),
        authentication: Some(vec![
            VerificationMethod::DIDURL(vm_url.clone()),
        ]),
        assertion_method: Some(vec![
            VerificationMethod::DIDURL(vm_url),
        ]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_poly(did: &str, account_address: String) -> ResolutionResult {
    if !account_address.starts_with("0x") {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        Value::String("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020".to_string()),
    );
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: "eip155:137".to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("Recovery2020".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm]),
        authentication: Some(vec![
            VerificationMethod::DIDURL(vm_url.clone()),
        ]),
        assertion_method: Some(vec![
            VerificationMethod::DIDURL(vm_url),
        ]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_sol(did: &str, account_address: String) -> ResolutionResult {
    let public_key_bytes = match bs58::decode(&account_address).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return resolution_error(&ERROR_INVALID_DID),
    };
    if public_key_bytes.len() != 32 {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "publicKeyJwk".to_string(),
        serde_json::json!({
            "@id": "https://w3id.org/security#publicKeyJwk",
            "@type": "@json"
        }),
    );
    context.insert(
        "Ed25519VerificationKey2018".to_string(),
        Value::String("https://w3id.org/security#Ed25519VerificationKey2018".to_string()),
    );
    context.insert(
        "SolanaMethod2021".to_string(),
        Value::String("https://w3id.org/security#SolanaMethod2021".to_string()),
    );
    let pk_jwk = JWK {
        params: Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public_key_bytes),
            private_key: None,
        }),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: "solana".to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("controller".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "Ed25519VerificationKey2018".to_string(),
        public_key_jwk: Some(pk_jwk.clone()),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let solvm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("SolanaMethod2021".to_string()),
        ..Default::default()
    };
    let solvm = VerificationMethod::Map(VerificationMethodMap {
        id: solvm_url.to_string(),
        type_: "SolanaMethod2021".to_string(),
        public_key_jwk: Some(pk_jwk.clone()),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm, solvm]),
        authentication: Some(vec![
            VerificationMethod::DIDURL(vm_url.clone()),
            VerificationMethod::DIDURL(solvm_url.clone()),
        ]),
        assertion_method: Some(vec![
            VerificationMethod::DIDURL(vm_url),
            VerificationMethod::DIDURL(solvm_url),
        ]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_btc(did: &str, account_address: String) -> ResolutionResult {
    if !account_address.starts_with("1") {
        return resolution_error(&ERROR_INVALID_DID);
    };
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: CHAIN_ID_BITCOIN_MAINNET.to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("blockchainAccountId".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: String::from(vm_url.clone()),
        type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        Value::String("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020".to_string()),
    );
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm]),
        authentication: Some(vec![VerificationMethod::DIDURL(vm_url.clone())]),
        assertion_method: Some(vec![VerificationMethod::DIDURL(vm_url)]),
        ..Default::default()
    };
    resolution_result(doc)
}

async fn resolve_doge(did: &str, account_address: String) -> ResolutionResult {
    if !account_address.starts_with("D") {
        return resolution_error(&ERROR_INVALID_DID);
    }
    let mut context = BTreeMap::new();
    context.insert(
        "blockchainAccountId".to_string(),
        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
    );
    context.insert(
        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        Value::String("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020".to_string()),
    );
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: CHAIN_ID_DOGECOIN_MAINNET.to_string(),
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some("blockchainAccountId".to_string()),
        ..Default::default()
    };
    let vm = VerificationMethod::Map(VerificationMethodMap {
        id: String::from(vm_url.clone()),
        type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
        controller: did.to_string(),
        blockchain_account_id: Some(blockchain_account_id.to_string()),
        ..Default::default()
    });
    let doc = Document {
        context: Contexts::Many(vec![
            Context::URI(DEFAULT_CONTEXT.to_string()),
            Context::Object(context),
        ]),
        id: did.to_string(),
        verification_method: Some(vec![vm]),
        authentication: Some(vec![VerificationMethod::DIDURL(vm_url.clone())]),
        assertion_method: Some(vec![VerificationMethod::DIDURL(vm_url)]),
        ..Default::default()
    };
    resolution_result(doc)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDPKH {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> ResolutionResult {
        let (type_, data) = match did.splitn(4, ':').collect::<Vec<&str>>().as_slice() {
            ["did", "pkh", type_, data] => (type_.to_string(), data.to_string()),
            _ => return resolution_error(&ERROR_INVALID_DID),
        };

        match &type_[..] {
            "tz" => resolve_tz(did, data).await,
            "eth" => resolve_eth(did, data).await,
            "celo" => resolve_celo(did, data).await,
            "poly" => resolve_poly(did, data).await,
            "sol" => resolve_sol(did, data).await,
            "btc" => resolve_btc(did, data).await,
            "doge" => resolve_doge(did, data).await,
            _ => resolution_error(&ERROR_INVALID_DID),
        }
    }

    fn to_did_method(&self) -> Option<&dyn DIDMethod> {
        Some(self)
    }
}

fn generate_sol(jwk: &JWK) -> Option<String> {
    match jwk.params {
        Params::OKP(ref params) if params.curve == "Ed25519" => {
            Some(bs58::encode(&params.public_key.0).into_string())
        }
        _ => None,
    }
}

fn generate_btc(key: &JWK) -> Result<String, String> {
    let addr = ssi::ripemd::hash_public_key(key, 0x00)?;
    #[cfg(test)]
    if !addr.starts_with("1") {
        return Err("Expected Bitcoin address".to_string());
    }
    Ok(addr)
}

fn generate_doge(key: &JWK) -> Result<String, String> {
    let addr = ssi::ripemd::hash_public_key(key, 0x1e)?;
    #[cfg(test)]
    if !addr.starts_with("D") {
        return Err("Expected Dogecoin address".to_string());
    }
    Ok(addr)
}

impl DIDMethod for DIDPKH {
    fn name(&self) -> &'static str {
        return "pkh";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let (key, pkh_name) = match source {
            Source::KeyAndPattern(key, pattern) => (key, pattern),
            _ => return None,
        };
        let addr = match match &pkh_name[..] {
            "tz" => ssi::blakesig::hash_public_key(key).ok(),
            "eth" => ssi::keccak_hash::hash_public_key(key).ok(),
            "celo" => ssi::keccak_hash::hash_public_key(key).ok(),
            "poly" => ssi::keccak_hash::hash_public_key(key).ok(),
            "sol" => generate_sol(key),
            "btc" => generate_btc(key).ok(),
            "doge" => generate_doge(key).ok(),
            _ => None,
        } {
            Some(addr) => addr,
            None => return None,
        };
        let did = format!("did:pkh:{}:{}", pkh_name, addr);
        Some(did)
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, from_value, json};
    use ssi::jwk::Algorithm;
    use ssi::ldp::ProofSuite;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::Proof;

    fn test_generate(jwk_value: Value, type_: &str, did_expected: &str) {
        let jwk: JWK = from_value(jwk_value).unwrap();
        let did = DIDPKH
            .generate(&Source::KeyAndPattern(&jwk, type_))
            .unwrap();
        assert_eq!(did, did_expected);
    }

    #[test]
    fn generate_did_pkh() {
        let secp256k1_pk = json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
        });
        test_generate(
            secp256k1_pk.clone(),
            "eth",
            "did:pkh:eth:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758",
        );
        test_generate(
            secp256k1_pk.clone(),
            "celo",
            "did:pkh:celo:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758",
        );
        test_generate(
            secp256k1_pk.clone(),
            "poly",
            "did:pkh:poly:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758",
        );
        test_generate(
            json!({
                "kty": "OKP",
                "crv": "EdBlake2b",
                "x": "GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==",
                "d": "K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-"
            }),
            "tz",
            "did:pkh:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        );
        test_generate(
            secp256k1_pk.clone(),
            "tz",
            "did:pkh:tz:tz2CA2f3SWWcqbWsjHsMZPZxCY5iafSN3nDz",
        );
        test_generate(
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4",
                "y": "OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"
            }),
            "tz",
            "did:pkh:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
        );
    }

    async fn test_resolve(did: &str, doc_str_expected: &str) {
        let (res_meta, doc_opt, _meta_opt) = DIDPKH
            .resolve(did, &ResolutionInputMetadata::default())
            .await;
        eprintln!("{}", did);
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: Document = serde_json::from_str(doc_str_expected).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
        );
    }

    async fn test_resolve_error(did: &str, error_expected: &str) {
        let (res_meta, doc_opt, _meta_opt) = DIDPKH
            .resolve(did, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(doc_opt, None);
        assert_eq!(res_meta.error.unwrap(), error_expected);
    }

    #[tokio::test]
    async fn resolve_did_pkh() {
        test_resolve(
            "did:pkh:tz:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
            include_str!("../tests/did-tz1.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
            include_str!("../tests/did-tz2.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
            include_str!("../tests/did-tz3.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:eth:0xb9c5714089478a327f09197987f16f9e5d936e8a",
            include_str!("../tests/did-eth.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:celo:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011",
            include_str!("../tests/did-celo.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:poly:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5",
            include_str!("../tests/did-poly.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev",
            include_str!("../tests/did-sol.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:btc:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6",
            include_str!("../tests/did-btc.jsonld"),
        )
        .await;
        test_resolve(
            "did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
            include_str!("../tests/did-doge.jsonld"),
        )
        .await;
        test_resolve_error("did:pkh:tz:foo", ERROR_INVALID_DID).await;
        test_resolve_error("did:pkh:eth:bar", ERROR_INVALID_DID).await;
    }

    fn fuzz_proof_value(proof: &mut Option<OneOrMany<Proof>>) {
        match proof {
            Some(OneOrMany::One(ref mut proof)) => match proof {
                Proof {
                    jws: Some(ref mut jws),
                    ..
                } => {
                    jws.insert(0, 'x');
                }
                Proof {
                    proof_value: Some(ref mut value),
                    ..
                } => {
                    value.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }

    async fn credential_prove_verify_did_pkh(
        key: JWK,
        wrong_key: JWK,
        type_: &str,
        vm_relative_url: &str,
        proof_suite: &dyn ProofSuite,
        eip712_domain_opt: Option<ssi::eip712::ProofInfo>,
        vp_eip712_domain_opt: Option<ssi::eip712::ProofInfo>,
    ) {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};
        let did = DIDPKH
            .generate(&Source::KeyAndPattern(&key, type_))
            .unwrap();
        eprintln!("did: {}", did);
        let mut vc: Credential = from_value(json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": did.clone(),
            "issuanceDate": "2021-03-18T16:38:25Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(did.to_string() + vm_relative_url)),
            eip712_domain: eip712_domain_opt,
            ..Default::default()
        };
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        /*
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        */
        // Sign with proof suite directly because there is not currently a way to do it
        // for Eip712Signature2021 in did-pkh otherwise.
        let proof = proof_suite
            .sign(&vc, &issue_options, &DIDPKH, &key, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDPKH).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:pkh:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDPKH).await.errors.len() > 0);

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let proof_bad = proof_suite
            .sign(&vc_no_proof, &issue_options, &DIDPKH, &wrong_key, None)
            .await
            .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(vc_wrong_key.verify(None, &DIDPKH).await.errors.len() > 0);

        // Mess with proof signature to make verify fail
        let mut vc_fuzzed = vc.clone();
        fuzz_proof_value(&mut vc_fuzzed.proof);
        let vp_verification_result = vc_fuzzed.verify(None, &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // Make it into a VP
        use ssi::vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            id: None,
            context: ssi::vc::Contexts::Many(vec![ssi::vc::Context::URI(ssi::vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method = Some(URI::String(did.to_string() + vm_relative_url));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        vp_issue_options.eip712_domain = vp_eip712_domain_opt;
        // let vp_proof = vp.generate_proof(&key, &vp_issue_options).await.unwrap();
        let vp_proof = proof_suite
            .sign(&vp, &vp_issue_options, &DIDPKH, &key, None)
            .await
            .unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // Mess with proof signature to make verify fail
        let mut vp_fuzzed = vp.clone();
        fuzz_proof_value(&mut vp_fuzzed.proof);
        let vp_verification_result = vp_fuzzed.verify(Some(vp_issue_options), &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // Test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:pkh:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDPKH).await.errors.len() > 0);
    }

    async fn credential_prepare_complete_verify_did_pkh_tz(
        algorithm: Algorithm,
        key: JWK,
        wrong_key: JWK,
        type_: &str,
        vm_relative_url: &str,
        proof_suite: &dyn ProofSuite,
    ) {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};
        let did = DIDPKH
            .generate(&Source::KeyAndPattern(&key, type_))
            .unwrap();
        eprintln!("did: {}", did);
        let mut vc: Credential = from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "issuer": did.clone(),
            "issuanceDate": "2021-03-18T16:38:25Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(did.to_string() + vm_relative_url)),
            ..Default::default()
        };
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        let prep = proof_suite
            .prepare(&vc, &issue_options, &DIDPKH, &key, None)
            .await
            .unwrap();

        let sig = sign_tezos(&prep, algorithm, &key);
        eprintln!("sig: {}", sig);

        // Complete issuance
        let proof = proof_suite.complete(prep, &sig).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDPKH).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:pkh:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDPKH).await.errors.len() > 0);

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let proof_bad = proof_suite
            .sign(&vc_no_proof, &issue_options, &DIDPKH, &wrong_key, None)
            .await
            .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(vc_wrong_key.verify(None, &DIDPKH).await.errors.len() > 0);

        // Mess with proof signature to make verify fail
        let mut vc_fuzzed = vc.clone();
        fuzz_proof_value(&mut vc_fuzzed.proof);
        let vp_verification_result = vc_fuzzed.verify(None, &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // Make it into a VP
        use ssi::vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            id: None,
            context: ssi::vc::Contexts::Many(vec![ssi::vc::Context::URI(ssi::vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method = Some(URI::String(did.to_string() + vm_relative_url));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);

        let prep = proof_suite
            .prepare(&vp, &vp_issue_options, &DIDPKH, &key, None)
            .await
            .unwrap();
        let sig = sign_tezos(&prep, algorithm, &key);
        let vp_proof = proof_suite.complete(prep, &sig).await.unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // Mess with proof signature to make verify fail
        let mut vp_fuzzed = vp.clone();
        fuzz_proof_value(&mut vp_fuzzed.proof);
        let vp_verification_result = vp_fuzzed.verify(Some(vp_issue_options), &DIDPKH).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // Test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:pkh:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDPKH).await.errors.len() > 0);
    }

    fn sign_tezos(prep: &ssi::ldp::ProofPreparation, algorithm: Algorithm, key: &JWK) -> String {
        // Simulate signing with a Tezos wallet
        let micheline = match prep.signing_input {
            ssi::ldp::SigningInput::Micheline { ref micheline } => hex::decode(micheline).unwrap(),
            _ => panic!("Expected Micheline expression for signing"),
        };
        ssi::tzkey::sign_tezos(&micheline, algorithm, key).unwrap()
    }

    #[tokio::test]
    async fn resolve_vc_issue_verify() {
        let key_secp256k1: JWK =
            from_str(include_str!("../../tests/secp256k1-2021-02-17.json")).unwrap();
        let key_secp256k1_recovery = JWK {
            algorithm: Some(Algorithm::ES256KR),
            ..key_secp256k1.clone()
        };
        let key_secp256k1_eip712sig = JWK {
            algorithm: Some(Algorithm::ES256KR),
            key_operations: Some(vec!["signTypedData".to_string()]),
            ..key_secp256k1.clone()
        };
        let key_secp256k1_epsig = JWK {
            algorithm: Some(Algorithm::ES256KR),
            key_operations: Some(vec!["signPersonalMessage".to_string()]),
            ..key_secp256k1.clone()
        };

        let mut key_ed25519: JWK =
            from_str(include_str!("../../tests/ed25519-2020-10-18.json")).unwrap();
        let mut key_p256: JWK =
            from_str(include_str!("../../tests/secp256r1-2021-03-18.json")).unwrap();
        let other_key_secp256k1 = JWK::generate_secp256k1().unwrap();
        let mut other_key_ed25519 = JWK::generate_ed25519().unwrap();
        let mut other_key_p256 = JWK::generate_p256().unwrap();

        // eth/Recovery2020
        credential_prove_verify_did_pkh(
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "eth",
            "#Recovery2020",
            &ssi::ldp::EcdsaSecp256k1RecoverySignature2020,
            None,
            None,
        )
        .await;

        // eth/Eip712
        credential_prove_verify_did_pkh(
            key_secp256k1_eip712sig.clone(),
            other_key_secp256k1.clone(),
            "eth",
            "#Recovery2020",
            &ssi::ldp::Eip712Signature2021,
            None,
            None,
        )
        .await;

        // eth/Eip712
        let eip712_domain: ssi::eip712::ProofInfo = serde_json::from_value(json!({
          "messageSchema": {
            "EIP712Domain": [
              { "name": "name", "type": "string" }
            ],
            "VerifiableCredential": [
              { "name": "@context", "type": "string[]" },
              { "name": "type", "type": "string[]" },
              { "name": "issuer", "type": "string" },
              { "name": "issuanceDate", "type": "string" },
              { "name": "credentialSubject", "type": "CredentialSubject" },
              { "name": "proof", "type": "Proof" }
            ],
            "CredentialSubject": [
              { "name": "id", "type": "string" },
            ],
            "Proof": [
              { "name": "@context", "type": "string" },
              { "name": "verificationMethod", "type": "string" },
              { "name": "created", "type": "string" },
              { "name": "proofPurpose", "type": "string" },
              { "name": "type", "type": "string" }
            ]
          },
          "domain": {
            "name": "EthereumEip712Signature2021",
          },
          "primaryType": "VerifiableCredential"
        }))
        .unwrap();
        let vp_eip712_domain: ssi::eip712::ProofInfo = serde_json::from_value(json!({
          "messageSchema": {
            "EIP712Domain": [
              { "name": "name", "type": "string" }
            ],
            "VerifiablePresentation": [
              { "name": "@context", "type": "string[]" },
              { "name": "type", "type": "string" },
              { "name": "holder", "type": "string" },
              { "name": "verifiableCredential", "type": "VerifiableCredential" },
              { "name": "proof", "type": "Proof" }
            ],
            "VerifiableCredential": [
              { "name": "@context", "type": "string[]" },
              { "name": "type", "type": "string[]" },
              { "name": "issuer", "type": "string" },
              { "name": "issuanceDate", "type": "string" },
              { "name": "credentialSubject", "type": "CredentialSubject" },
              { "name": "proof", "type": "Proof" }
            ],
            "CredentialSubject": [
              { "name": "id", "type": "string" },
            ],
            "Proof": [
              { "name": "@context", "type": "string" },
              { "name": "verificationMethod", "type": "string" },
              { "name": "created", "type": "string" },
              { "name": "proofPurpose", "type": "string" },
              { "name": "proofValue", "type": "string" },
              { "name": "eip712Domain", "type": "EIP712Info" },
              { "name": "type", "type": "string" }
            ],
            "EIP712Info": [
              { "name": "domain", "type": "EIP712Domain" },
              { "name": "primaryType", "type": "string" },
              { "name": "messageSchema", "type": "Types" },
            ],
            "Types": [
              { "name": "EIP712Domain", "type": "Type[]" },
              { "name": "VerifiableCredential", "type": "Type[]" },
              { "name": "CredentialSubject", "type": "Type[]" },
              { "name": "Proof", "type": "Type[]" },
            ],
            "Type": [
              { "name": "name", "type": "string" },
              { "name": "type", "type": "string" }
            ]
          },
          "domain": {
            "name": "EthereumEip712Signature2021",
          },
          "primaryType": "VerifiablePresentation"
        }))
        .unwrap();
        credential_prove_verify_did_pkh(
            key_secp256k1_eip712sig.clone(),
            other_key_secp256k1.clone(),
            "eth",
            "#Recovery2020",
            &ssi::ldp::EthereumEip712Signature2021,
            Some(eip712_domain),
            Some(vp_eip712_domain),
        )
        .await;

        // eth/Eip712
        credential_prove_verify_did_pkh(
            key_secp256k1_epsig.clone(),
            other_key_secp256k1.clone(),
            "eth",
            "#Recovery2020",
            &ssi::ldp::Eip712Signature2021,
            None,
            None,
        )
        .await;

        println!("did:pkh:tz:tz1");
        key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        other_key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        credential_prove_verify_did_pkh(
            key_ed25519.clone(),
            other_key_ed25519.clone(),
            "tz",
            "#blockchainAccountId",
            &ssi::ldp::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            None,
            None,
        )
        .await;
        key_ed25519.algorithm = Some(Algorithm::EdDSA);
        other_key_ed25519.algorithm = Some(Algorithm::EdDSA);

        // TODO
        // println!("did:pkh:tz:tz2");
        // credential_prove_verify_did_pkh(
        //     key_secp256k1_recovery.clone(),
        //     other_key_secp256k1.clone(),
        //     "tz",
        //     "#blockchainAccountId",
        //     &ssi::ldp::EcdsaSecp256k1RecoverySignature2020,
        // )
        // .await;

        println!("did:pkh:tz:tz3");
        key_p256.algorithm = Some(Algorithm::ESBlake2b);
        other_key_p256.algorithm = Some(Algorithm::ESBlake2b);
        credential_prove_verify_did_pkh(
            key_p256.clone(),
            other_key_p256.clone(),
            "tz",
            "#blockchainAccountId",
            &ssi::ldp::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            None,
            None,
        )
        .await;
        key_p256.algorithm = Some(Algorithm::ES256);
        other_key_p256.algorithm = Some(Algorithm::ES256);

        println!("did:pkh:sol");
        credential_prove_verify_did_pkh(
            key_ed25519.clone(),
            other_key_ed25519.clone(),
            "sol",
            "#controller",
            &ssi::ldp::Ed25519Signature2018,
            None,
            None,
        )
        .await;

        /*
        println!("did:pkh:sol - SolanaMethod2021");
        credential_prove_verify_did_pkh(
            key_ed25519.clone(),
            other_key_ed25519.clone(),
            "sol",
            "#SolanaMethod2021",
            &ssi::ldp::SolanaSignature2021,
        )
        .await;
        */

        println!("did:pkh:btc");
        credential_prove_verify_did_pkh(
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "btc",
            "#blockchainAccountId",
            &ssi::ldp::EcdsaSecp256k1RecoverySignature2020,
            None,
            None,
        )
        .await;

        println!("did:pkh:doge");
        credential_prove_verify_did_pkh(
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "doge",
            "#blockchainAccountId",
            &ssi::ldp::EcdsaSecp256k1RecoverySignature2020,
            None,
            None,
        )
        .await;

        println!("did:pkh:tz:tz1 - TezosMethod2021");
        key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        other_key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        credential_prepare_complete_verify_did_pkh_tz(
            Algorithm::EdBlake2b,
            key_ed25519.clone(),
            other_key_ed25519.clone(),
            "tz",
            "#TezosMethod2021",
            &ssi::ldp::TezosSignature2021,
        )
        .await;
        key_ed25519.algorithm = Some(Algorithm::EdDSA);
        other_key_ed25519.algorithm = Some(Algorithm::EdDSA);

        /* https://github.com/spruceid/ssi/issues/194
        println!("did:pkh:tz:tz2 - TezosMethod2021");
        credential_prepare_complete_verify_did_pkh_tz(
            Algorithm::ESBlake2bK,
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "tz",
            "#TezosMethod2021",
            &ssi::ldp::TezosSignature2021,
        )
        .await;
        */

        println!("did:pkh:tz:tz3 - TezosMethod2021");
        key_p256.algorithm = Some(Algorithm::ESBlake2b);
        other_key_p256.algorithm = Some(Algorithm::ESBlake2b);
        credential_prepare_complete_verify_did_pkh_tz(
            Algorithm::ESBlake2b,
            key_p256.clone(),
            other_key_p256.clone(),
            "tz",
            "#TezosMethod2021",
            &ssi::ldp::TezosSignature2021,
        )
        .await;
        key_p256.algorithm = Some(Algorithm::ES256);
        other_key_p256.algorithm = Some(Algorithm::ES256);
    }

    async fn test_verify_vc(vc_str: &str, num_warnings: usize) {
        let mut vc = ssi::vc::Credential::from_json_unsigned(vc_str).unwrap();
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDPKH).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
        assert_eq!(verification_result.warnings.len(), num_warnings);
        // Negative test: tamper with the VC and watch verification fail.
        let mut map = std::collections::HashMap::new();
        map.insert("foo".to_string(), serde_json::json!("bar"));
        vc.property_set = Some(map);
        let verification_result = vc.verify(None, &DIDPKH).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.len() > 0);
    }

    #[tokio::test]
    async fn verify_vc() {
        test_verify_vc(include_str!("../tests/vc-tz1.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-tz1-jcs.jsonld"), 1).await;
        test_verify_vc(include_str!("../tests/vc-eth-eip712sig.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-eth-eip712vm.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-eth-epsig.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-celo-epsig.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-poly-epsig.jsonld"), 0).await;
        test_verify_vc(include_str!("../tests/vc-poly-eip712sig.jsonld"), 0).await;
    }
}
