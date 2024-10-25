use iref::Iri;
use ssi_dids_core::document::representation::MediaType;
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::{document, resolution, DIDBuf, DIDMethod};
use ssi_dids_core::{document::representation, resolution::Output};
use static_iref::iri;
use std::collections::BTreeMap;
use std::str::FromStr;

use ssi_caips::caip10::BlockchainAccountId;
use ssi_caips::caip2::ChainId;
use ssi_dids_core::{
    document::DIDVerificationMethod,
    resolution::{DIDMethodResolver, Error},
    DIDURLBuf, Document, DID,
};
use ssi_jwk::{Base64urlUInt, OctetParams, Params, JWK};

mod json_ld_context;

pub use json_ld_context::*;

#[derive(Debug, Clone, Copy)]
pub enum PkhVerificationMethodType {
    Ed25519VerificationKey2018,
    EcdsaSecp256k1RecoveryMethod2020,
    TezosMethod2021,
    SolanaMethod2021,
    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    BlockchainVerificationMethod2021,
}

impl PkhVerificationMethodType {
    // pub fn from_prefix(prefix: Prefix) -> Self {
    //     match prefix {
    //         Prefix::TZ1 | Prefix::KT1 => {
    //             Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
    //         }
    //         Prefix::TZ2 => VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020,
    //         Prefix::TZ3 => {
    //             VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
    //         }
    //     }
    // }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519VerificationKey2018 => "Ed25519VerificationKey2018",
            Self::TezosMethod2021 => "TezosMethod2021",
            Self::SolanaMethod2021 => "SolanaMethod2021",
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
            }
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
            }
            Self::BlockchainVerificationMethod2021 => "BlockchainVerificationMethod2021",
        }
    }

    pub fn as_iri(&self) -> &'static Iri {
        match self {
            Self::Ed25519VerificationKey2018 => iri!("https://w3id.org/security#Ed25519VerificationKey2018"),
            Self::TezosMethod2021 => iri!("https://w3id.org/security#TezosMethod2021"),
            Self::SolanaMethod2021 => iri!("https://w3id.org/security#SolanaMethod2021"),
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => iri!("https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"),
            Self::EcdsaSecp256k1RecoveryMethod2020 => iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => iri!("https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"),
            Self::BlockchainVerificationMethod2021 => iri!("https://w3id.org/security#BlockchainVerificationMethod2021")
        }
    }
}

pub struct PkhVerificationMethod {
    pub id: DIDURLBuf,
    pub type_: PkhVerificationMethodType,
    pub controller: DIDBuf,
    pub blockchain_account_id: BlockchainAccountId,
    pub public_key: Option<PublicKey>,
}

pub enum PublicKey {
    Jwk(Box<JWK>),
    Base58(String),
}

impl From<PkhVerificationMethod> for DIDVerificationMethod {
    fn from(value: PkhVerificationMethod) -> Self {
        let mut properties: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        properties.insert(
            "blockchainAccountId".to_owned(),
            value.blockchain_account_id.to_string().into(),
        );

        if let Some(key) = value.public_key {
            match key {
                PublicKey::Jwk(jwk) => {
                    properties.insert(
                        "publicKeyJwk".to_owned(),
                        serde_json::to_value(jwk).unwrap(),
                    );
                }
                PublicKey::Base58(key) => {
                    properties.insert("publicKeyBase58".to_owned(), key.into());
                }
            }
        }

        Self {
            id: value.id,
            type_: value.type_.name().to_owned(),
            controller: value.controller,
            properties,
        }
    }
}

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-3.md
const REFERENCE_EIP155_ETHEREUM_MAINNET: &str = "1";

const REFERENCE_EIP155_CELO_MAINNET: &str = "42220";
const REFERENCE_EIP155_POLYGON_MAINNET: &str = "137";

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-4.md
const REFERENCE_BIP122_BITCOIN_MAINNET: &str = "000000000019d6689c085ae165831e93";

const REFERENCE_BIP122_DOGECOIN_MAINNET: &str = "1a91e3dace36e2be3bf030a65679fe82";

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-26.md
const REFERENCE_TEZOS_MAINNET: &str = "NetXdQprcVkpaWU";

// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-30.md
const REFERENCE_SOLANA_MAINNET: &str = "4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ";

/// did:pkh DID Method
///
/// See: <https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md>
pub struct DIDPKH;

type ResolutionResult = Result<(Document, JsonLdContext), Error>;

async fn resolve_tezos(did: &DID, account_address: &str, reference: &str) -> ResolutionResult {
    if account_address.len() < 3 {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }

    let vm_type = match account_address.get(0..3) {
        Some("tz1") => {
            PkhVerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
        }
        Some("tz2") => PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020,
        Some("tz3") => {
            PkhVerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
        }
        _ => {
            return Err(Error::InvalidMethodSpecificId(
                did.method_specific_id().to_owned(),
            ))
        }
    };

    let blockchain_account_id = BlockchainAccountId {
        account_address: account_address.to_owned(),
        chain_id: ChainId {
            namespace: "tezos".to_string(),
            reference: reference.to_string(),
        },
    };

    let vm_url = DIDURLBuf::from_string(format!("{did}#blockchainAccountId")).unwrap();
    let vm = PkhVerificationMethod {
        id: vm_url.clone(),
        type_: vm_type,
        controller: did.to_owned(),
        blockchain_account_id: blockchain_account_id.clone(),
        public_key: None,
    };

    let vm2_url = DIDURLBuf::from_string(format!("{did}#TezosMethod2021")).unwrap();
    let vm2 = PkhVerificationMethod {
        id: vm2_url.clone(),
        type_: PkhVerificationMethodType::TezosMethod2021,
        controller: did.to_owned(),
        blockchain_account_id,
        public_key: None,
    };

    let mut json_ld_context = JsonLdContext::default();
    json_ld_context.add_verification_method(&vm);
    json_ld_context.add_verification_method(&vm2);

    let mut doc = Document::new(did.to_owned());
    doc.verification_method.extend([vm.into(), vm2.into()]);
    doc.verification_relationships.authentication.extend([
        ValueOrReference::Reference(vm_url.clone().into()),
        ValueOrReference::Reference(vm2_url.clone().into()),
    ]);
    doc.verification_relationships.assertion_method.extend([
        ValueOrReference::Reference(vm_url.into()),
        ValueOrReference::Reference(vm2_url.into()),
    ]);

    Ok((doc, json_ld_context))
}

async fn resolve_eip155(
    did: &DID,
    account_address: &str,
    reference: &str,
    legacy: bool,
) -> ResolutionResult {
    if !account_address.starts_with("0x") {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }

    let blockchain_account_id = BlockchainAccountId {
        account_address: account_address.to_owned(),
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference: reference.to_string(),
        },
    };
    let vm_fragment = if legacy {
        // Explanation of fragment differences:
        //   https://github.com/spruceid/ssi/issues/297
        "Recovery2020"
    } else {
        "blockchainAccountId"
    };
    let vm_url = DIDURLBuf::from_string(format!("{did}#{vm_fragment}")).unwrap();
    let vm = PkhVerificationMethod {
        id: vm_url.clone(),
        type_: PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020,
        controller: did.to_owned(),
        blockchain_account_id,
        public_key: None,
    };

    let mut json_ld_context = JsonLdContext::default();
    json_ld_context.add_verification_method(&vm);

    let mut doc = Document::new(did.to_owned());
    doc.verification_method.push(vm.into());
    doc.verification_relationships
        .authentication
        .push(ValueOrReference::Reference(vm_url.clone().into()));
    doc.verification_relationships
        .assertion_method
        .push(ValueOrReference::Reference(vm_url.into()));

    Ok((doc, json_ld_context))
}

async fn resolve_solana(did: &DID, account_address: &str, reference: &str) -> ResolutionResult {
    let public_key_bytes = match bs58::decode(&account_address).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(Error::InvalidMethodSpecificId(
                did.method_specific_id().to_owned(),
            ))
        }
    };
    if public_key_bytes.len() != 32 {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }
    let chain_id = ChainId {
        namespace: "solana".to_string(),
        reference: reference.to_string(),
    };

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
        account_address: account_address.to_owned(),
        chain_id,
    };
    let vm_url = DIDURLBuf::from_string(format!("{did}#controller")).unwrap();
    let vm = PkhVerificationMethod {
        id: vm_url.clone(),
        type_: PkhVerificationMethodType::Ed25519VerificationKey2018,
        public_key: Some(PublicKey::Base58(account_address.to_owned())),
        controller: did.to_owned(),
        blockchain_account_id: blockchain_account_id.clone(),
    };
    let solvm_url = DIDURLBuf::from_string(format!("{did}#SolanaMethod2021")).unwrap();
    let solvm = PkhVerificationMethod {
        id: solvm_url.clone(),
        type_: PkhVerificationMethodType::SolanaMethod2021,
        public_key: Some(PublicKey::Jwk(Box::new(pk_jwk))),
        controller: did.to_owned(),
        blockchain_account_id,
    };

    let mut json_ld_context = JsonLdContext::default();
    json_ld_context.add_verification_method(&vm);
    json_ld_context.add_verification_method(&solvm);

    let mut doc = Document::new(did.to_owned());
    doc.verification_method.extend([vm.into(), solvm.into()]);
    doc.verification_relationships.authentication.extend([
        ValueOrReference::Reference(vm_url.clone().into()),
        ValueOrReference::Reference(solvm_url.clone().into()),
    ]);
    doc.verification_relationships.assertion_method.extend([
        ValueOrReference::Reference(vm_url.into()),
        ValueOrReference::Reference(solvm_url.into()),
    ]);

    Ok((doc, json_ld_context))
}

async fn resolve_bip122(did: &DID, account_address: &str, reference: &str) -> ResolutionResult {
    match reference {
        REFERENCE_BIP122_BITCOIN_MAINNET => {
            if !account_address.starts_with('1') {
                return Err(Error::InvalidMethodSpecificId(
                    did.method_specific_id().to_owned(),
                ));
            }
        }
        REFERENCE_BIP122_DOGECOIN_MAINNET => {
            if !account_address.starts_with('D') {
                return Err(Error::InvalidMethodSpecificId(
                    did.method_specific_id().to_owned(),
                ));
            }
        }
        _ => {
            // Unknown network address: no prefix hash check
        }
    }
    let blockchain_account_id = BlockchainAccountId {
        account_address: account_address.to_owned(),
        chain_id: ChainId {
            namespace: "bip122".to_string(),
            reference: reference.to_string(),
        },
    };
    let vm_url = DIDURLBuf::from_string(format!("{did}#blockchainAccountId")).unwrap();
    let vm = PkhVerificationMethod {
        id: vm_url.clone(),
        type_: PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020,
        controller: did.to_owned(),
        blockchain_account_id,
        public_key: None,
    };

    let mut json_ld_context = JsonLdContext::default();
    json_ld_context.add_verification_method(&vm);

    let mut doc = Document::new(did.to_owned());
    doc.verification_method.push(vm.into());
    doc.verification_relationships
        .authentication
        .push(ValueOrReference::Reference(vm_url.clone().into()));
    doc.verification_relationships
        .assertion_method
        .push(ValueOrReference::Reference(vm_url.into()));

    Ok((doc, json_ld_context))
}

async fn resolve_aleo(did: &DID, account_address: &str, reference: &str) -> ResolutionResult {
    use bech32::FromBase32;
    let (hrp, data, _variant) = match bech32::decode(account_address) {
        Err(_e) => {
            return Err(Error::InvalidMethodSpecificId(
                did.method_specific_id().to_owned(),
            ))
        }
        Ok(data) => data,
    };
    if data.is_empty() {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }
    if hrp != "aleo" {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }
    let data = match Vec::<u8>::from_base32(&data) {
        Err(_e) => {
            return Err(Error::InvalidMethodSpecificId(
                did.method_specific_id().to_owned(),
            ))
        }
        Ok(data) => data,
    };
    // Address data is decoded for validation only.
    // The verification method object just uses the account address in blockchainAccountId.
    if data.len() != 32 {
        return Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        ));
    }
    let chain_id = ChainId {
        namespace: "aleo".to_string(),
        reference: reference.to_string(),
    };
    let blockchain_account_id = BlockchainAccountId {
        account_address: account_address.to_owned(),
        chain_id,
    };
    let vm_url = DIDURLBuf::from_string(format!("{did}#blockchainAccountId")).unwrap();
    let vm = PkhVerificationMethod {
        id: vm_url.clone(),
        type_: PkhVerificationMethodType::BlockchainVerificationMethod2021,
        controller: did.to_owned(),
        blockchain_account_id,
        public_key: None,
    };

    let mut json_ld_context = JsonLdContext::default();
    json_ld_context.add_blockchain_2021_v1();
    json_ld_context.add_verification_method(&vm);

    let mut doc = Document::new(did.to_owned());
    doc.verification_method.push(vm.into());
    doc.verification_relationships
        .authentication
        .push(ValueOrReference::Reference(vm_url.clone().into()));
    doc.verification_relationships
        .assertion_method
        .push(ValueOrReference::Reference(vm_url.into()));

    Ok((doc, json_ld_context))
}

async fn resolve_caip10(did: &DID, account_id: &str) -> ResolutionResult {
    let account_id = match BlockchainAccountId::from_str(account_id) {
        Ok(account_id) => account_id,
        Err(_) => {
            return Err(Error::InvalidMethodSpecificId(
                did.method_specific_id().to_owned(),
            ))
        }
    };

    let namespace = account_id.chain_id.namespace;
    let reference = account_id.chain_id.reference;
    match &namespace[..] {
        "tezos" => resolve_tezos(did, &account_id.account_address, &reference).await,
        "eip155" => resolve_eip155(did, &account_id.account_address, &reference, false).await,
        "bip122" => resolve_bip122(did, &account_id.account_address, &reference).await,
        "solana" => resolve_solana(did, &account_id.account_address, &reference).await,
        "aleo" => resolve_aleo(did, &account_id.account_address, &reference).await,
        _ => Err(Error::InvalidMethodSpecificId(
            did.method_specific_id().to_owned(),
        )),
    }
}

impl DIDMethod for DIDPKH {
    const DID_METHOD_NAME: &'static str = "pkh";
}

impl DIDMethodResolver for DIDPKH {
    fn method_name(&self) -> &str {
        "pkh"
    }

    async fn resolve_method_representation<'a>(
        &'a self,
        id: &'a str,
        options: ssi_dids_core::resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let (type_, data) = id
            .split_once(':')
            .ok_or_else(|| Error::InvalidMethodSpecificId(id.to_owned()))?;

        let did = DIDBuf::from_string(format!("did:pkh:{id}")).unwrap();
        let (doc, json_ld_context) = match type_ {
            // Non-CAIP-10 (deprecated)
            "tz" => resolve_tezos(&did, data, REFERENCE_TEZOS_MAINNET).await,
            "eth" => resolve_eip155(&did, data, REFERENCE_EIP155_ETHEREUM_MAINNET, true).await,
            "celo" => resolve_eip155(&did, data, REFERENCE_EIP155_CELO_MAINNET, true).await,
            "poly" => resolve_eip155(&did, data, REFERENCE_EIP155_POLYGON_MAINNET, true).await,
            "sol" => resolve_solana(&did, data, REFERENCE_SOLANA_MAINNET).await,
            "btc" => resolve_bip122(&did, data, REFERENCE_BIP122_BITCOIN_MAINNET).await,
            "doge" => resolve_bip122(&did, data, REFERENCE_BIP122_DOGECOIN_MAINNET).await,
            // CAIP-10
            _ => {
                let account_id = type_.to_string() + ":" + data;
                resolve_caip10(&did, &account_id).await
            }
        }?;

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);
        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    json_ld_context.into_entries(),
                ),
            },
        ));

        Ok(Output::new(
            represented.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}

fn generate_sol(jwk: &JWK) -> Result<String, GenerateError> {
    match jwk.params {
        Params::OKP(ref params) if params.curve == "Ed25519" => {
            Ok(bs58::encode(&params.public_key.0).into_string())
        }
        _ => Err(GenerateError::UnsupportedKeyType),
    }
}

#[cfg(feature = "ripemd-160")]
fn generate_btc(key: &JWK) -> Result<String, GenerateError> {
    let addr = ssi_jwk::ripemd160::hash_public_key(key, 0x00).map_err(GenerateError::other)?;
    #[cfg(test)]
    if !addr.starts_with('1') {
        return Err(GenerateError::other("Expected Bitcoin address"));
    }
    Ok(addr)
}

#[cfg(feature = "ripemd-160")]
fn generate_doge(key: &JWK) -> Result<String, GenerateError> {
    let addr = ssi_jwk::ripemd160::hash_public_key(key, 0x1e).map_err(GenerateError::other)?;
    #[cfg(test)]
    if !addr.starts_with('D') {
        return Err(GenerateError::other("Expected Dogecoin address"));
    }
    Ok(addr)
}

#[cfg(feature = "tezos")]
fn generate_caip10_tezos(
    key: &JWK,
    ref_opt: Option<String>,
) -> Result<BlockchainAccountId, GenerateError> {
    let hash = ssi_jwk::blakesig::hash_public_key(key).map_err(GenerateError::other)?;
    let reference = ref_opt.unwrap_or_else(|| REFERENCE_TEZOS_MAINNET.to_string());
    Ok(BlockchainAccountId {
        account_address: hash,
        chain_id: ChainId {
            namespace: "tezos".to_string(),
            reference,
        },
    })
}

#[cfg(feature = "eip")]
fn generate_caip10_eip155(
    key: &JWK,
    ref_opt: Option<String>,
) -> Result<BlockchainAccountId, GenerateError> {
    let hash = ssi_jwk::eip155::hash_public_key_eip55(key).map_err(GenerateError::other)?;
    let reference = ref_opt.unwrap_or_else(|| REFERENCE_EIP155_ETHEREUM_MAINNET.to_string());
    Ok(BlockchainAccountId {
        account_address: hash,
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference,
        },
    })
}

#[cfg(feature = "ripemd-160")]
fn generate_caip10_bip122(
    key: &JWK,
    ref_opt: Option<String>,
) -> Result<BlockchainAccountId, GenerateError> {
    let reference = ref_opt.unwrap_or_else(|| REFERENCE_BIP122_BITCOIN_MAINNET.to_string());
    let addr;
    match &reference[..] {
        REFERENCE_BIP122_BITCOIN_MAINNET => {
            addr = ssi_jwk::ripemd160::hash_public_key(key, 0x00).map_err(GenerateError::other)?;
            if !addr.starts_with('1') {
                return Err(GenerateError::other("Expected Bitcoin address"));
            }
        }
        REFERENCE_BIP122_DOGECOIN_MAINNET => {
            addr = ssi_jwk::ripemd160::hash_public_key(key, 0x1e).map_err(GenerateError::other)?;
            if !addr.starts_with('D') {
                return Err(GenerateError::other("Expected Dogecoin address"));
            }
        }
        _ => {
            return Err(GenerateError::other("Expected Bitcoin address type"));
        }
    }

    Ok(BlockchainAccountId {
        account_address: addr,
        chain_id: ChainId {
            namespace: "bip122".to_string(),
            reference,
        },
    })
}

#[cfg(feature = "solana")]
fn generate_caip10_solana(
    key: &JWK,
    ref_opt: Option<String>,
) -> Result<BlockchainAccountId, GenerateError> {
    let reference = ref_opt.unwrap_or_default();
    let chain_id = ChainId {
        namespace: "solana".to_string(),
        reference,
    };
    let pk_bs58 = match key.params {
        Params::OKP(ref params) if params.curve == "Ed25519" => {
            bs58::encode(&params.public_key.0).into_string()
        }
        _ => return Err(GenerateError::UnsupportedKeyType),
    };
    Ok(BlockchainAccountId {
        account_address: pk_bs58,
        chain_id,
    })
}

#[cfg(feature = "aleo")]
fn generate_caip10_aleo(
    key: &JWK,
    ref_opt: Option<String>,
) -> Result<BlockchainAccountId, GenerateError> {
    let reference = ref_opt.unwrap_or_else(|| "1".to_string());
    let chain_id = ChainId {
        namespace: "aleo".to_string(),
        reference,
    };
    use bech32::ToBase32;
    let pk_bs58 = match key.params {
        Params::OKP(ref params) if params.curve == "AleoTestnet1Key" => bech32::encode(
            "aleo",
            params.public_key.0.to_base32(),
            bech32::Variant::Bech32m,
        )
        .unwrap(),
        _ => return Err(GenerateError::UnsupportedKeyType),
    };
    Ok(BlockchainAccountId {
        account_address: pk_bs58,
        chain_id,
    })
}

#[allow(unused, unreachable_code)]
fn generate_caip10_did(key: &JWK, name: &str) -> Result<DIDBuf, GenerateError> {
    // Require name to be a either CAIP-2 namespace or a
    // full CAIP-2 string - namespace and reference (e.g. internal
    // chain id or genesis hash).
    // If reference is not provided, default to a known mainnet.
    // If a reference is provided, pass it through.
    // Return a CAIP-10 string, appended to "did:pkh:".
    let (namespace, reference_opt) = match name.splitn(2, ':').collect::<Vec<&str>>().as_slice() {
        [namespace] => (namespace.to_string(), None),
        [namespace, reference] => (namespace.to_string(), Some(reference.to_string())),
        _ => return Err(GenerateError::InvalidChainId),
    };
    let account_id: BlockchainAccountId = match &namespace[..] {
        #[cfg(feature = "tezos")]
        "tezos" => generate_caip10_tezos(key, reference_opt)?,
        #[cfg(feature = "eip")]
        "eip155" => generate_caip10_eip155(key, reference_opt)?,
        #[cfg(feature = "ripemd-160")]
        "bip122" => generate_caip10_bip122(key, reference_opt)?,
        #[cfg(feature = "solana")]
        "solana" => generate_caip10_solana(key, reference_opt)?,
        #[cfg(feature = "aleo")]
        "aleo" => generate_caip10_aleo(key, reference_opt)?,
        _ => return Err(GenerateError::UnsupportedNamespace),
    };

    Ok(DIDBuf::from_string(format!("did:pkh:{}", account_id)).unwrap())
}

#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("Unable to parse chain id or namespace")]
    InvalidChainId,

    #[error("Namespace not supported")]
    UnsupportedNamespace,

    #[error("Unsupported key type")]
    UnsupportedKeyType,

    #[error("{0}")]
    Other(String),
}

impl GenerateError {
    pub fn other(e: impl ToString) -> Self {
        Self::Other(e.to_string())
    }
}

impl DIDPKH {
    pub fn generate(key: &JWK, pkh_name: &str) -> Result<DIDBuf, GenerateError> {
        let addr = match pkh_name {
            // Aliases for did:pkh pre-CAIP-10. Deprecate?
            #[cfg(feature = "tezos")]
            "tz" => ssi_jwk::blakesig::hash_public_key(key).map_err(GenerateError::other)?,
            #[cfg(feature = "eip")]
            "eth" => ssi_jwk::eip155::hash_public_key(key).map_err(GenerateError::other)?,
            #[cfg(feature = "eip")]
            "celo" => ssi_jwk::eip155::hash_public_key(key).map_err(GenerateError::other)?,
            #[cfg(feature = "eip")]
            "poly" => ssi_jwk::eip155::hash_public_key(key).map_err(GenerateError::other)?,
            "sol" => generate_sol(key)?,
            #[cfg(feature = "ripemd-160")]
            "btc" => generate_btc(key)?,
            #[cfg(feature = "ripemd-160")]
            "doge" => generate_doge(key)?,
            // CAIP-10/CAIP-2 chain id
            name => return generate_caip10_did(key, name),
        };

        Ok(DIDBuf::from_string(format!("did:pkh:{}:{}", pkh_name, addr)).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_claims::VerificationParameters;
    use ssi_dids_core::{did, resolution::ErrorKind, DIDResolver, VerificationMethodDIDResolver};

    #[cfg(all(feature = "eip", feature = "tezos"))]
    fn test_generate(jwk_value: serde_json::Value, type_: &str, did_expected: &str) {
        let jwk: JWK = serde_json::from_value(jwk_value).unwrap();
        let did = DIDPKH::generate(&jwk, type_).unwrap();
        assert_eq!(did, did_expected);
    }

    #[test]
    #[cfg(all(feature = "eip", feature = "tezos"))]
    fn generate_did_pkh() {
        use serde_json::json;

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
            secp256k1_pk,
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

    async fn test_resolve(did: &DID, doc_str_expected: &str) {
        let res = DIDPKH.resolve_with(did, Default::default()).await.unwrap();
        eprintln!("{}", did);
        let doc = res.document;
        eprintln!("resolved:\n{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: Document = serde_json::from_str(doc_str_expected).unwrap();
        eprintln!(
            "expected:\n{}",
            serde_json::to_string_pretty(&doc_expected).unwrap()
        );
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
        );
    }

    async fn test_resolve_error(did: &DID, error_expected: ErrorKind) {
        let res = DIDPKH.resolve(did).await;
        assert_eq!(res.err().unwrap().kind(), error_expected);
    }

    #[tokio::test]
    async fn resolve_did_pkh() {
        // CAIP-10-based
        test_resolve(
            did!("did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"),
            include_str!("../tests/did-tz1.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"),
            include_str!("../tests/did-tz2.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"),
            include_str!("../tests/did-tz3.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
            include_str!("../tests/did-eth.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011"),
            include_str!("../tests/did-celo.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5"),
            include_str!("../tests/did-poly.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"),
            include_str!("../tests/did-sol.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"),
            include_str!("../tests/did-btc.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
            include_str!("../tests/did-doge.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:aleo:1:aleo1y90yg3yzs4g7q25f9nn8khuu00m8ysynxmcw8aca2d0phdx8dgpq4vw348"),
            include_str!("../tests/did-aleo.jsonld"),
        )
        .await;

        // non-CAIP-10 (deprecated)
        test_resolve(
            did!("did:pkh:tz:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"),
            include_str!("../tests/did-tz1-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"),
            include_str!("../tests/did-tz2-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"),
            include_str!("../tests/did-tz3-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:eth:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
            include_str!("../tests/did-eth-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:celo:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011"),
            include_str!("../tests/did-celo-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:poly:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5"),
            include_str!("../tests/did-poly-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"),
            include_str!("../tests/did-sol-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:btc:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"),
            include_str!("../tests/did-btc-legacy.jsonld"),
        )
        .await;
        test_resolve(
            did!("did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
            include_str!("../tests/did-doge-legacy.jsonld"),
        )
        .await;

        test_resolve_error(did!("did:pkh:tz:foo"), ErrorKind::InvalidMethodSpecificId).await;
        test_resolve_error(did!("did:pkh:eth:bar"), ErrorKind::InvalidMethodSpecificId).await;
    }

    #[cfg(all(feature = "eip", feature = "tezos"))]
    async fn credential_prove_verify_did_pkh(
        key: JWK,
        wrong_key: JWK,
        type_: &str,
        vm_relative_url: &str,
        proof_suite: ssi_claims::data_integrity::AnySuite,
        eip712_domain_opt: Option<
            ssi_claims::data_integrity::suites::ethereum_eip712_signature_2021::Eip712Options,
        >,
        vp_eip712_domain_opt: Option<
            ssi_claims::data_integrity::suites::ethereum_eip712_signature_2021::Eip712Options,
        >,
    ) {
        use iref::IriBuf;
        use ssi_claims::{
            data_integrity::{
                signing::AlterSignature, AnyInputSuiteOptions, CryptographicSuite, ProofOptions,
            },
            vc::{
                syntax::NonEmptyVec,
                v1::{JsonCredential, JsonPresentation},
            },
            VerificationParameters,
        };
        use ssi_verification_methods_core::{ProofPurpose, SingleSecretSigner};
        use static_iref::uri;

        let didpkh = VerificationMethodDIDResolver::new(DIDPKH);
        let params = VerificationParameters::from_resolver(&didpkh);

        // use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};
        let did = DIDPKH::generate(&key, type_).unwrap();

        eprintln!("did: {}", did);
        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-03-18T16:38:25Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            })),
        );

        let issuance_date = cred.issuance_date.clone().unwrap();
        let created_date =
            xsd_types::DateTimeStamp::new(issuance_date.date_time, issuance_date.offset.unwrap());
        let issue_options = ProofOptions::new(
            created_date,
            IriBuf::new(did.to_string() + vm_relative_url)
                .unwrap()
                .into(),
            ProofPurpose::Assertion,
            AnyInputSuiteOptions {
                eip712: eip712_domain_opt.clone(),
                // eip712_v0_1: eip712_domain_opt.clone().map(Into::into),
                ..Default::default()
            }
            .with_public_key(key.to_public())
            .unwrap(),
        );
        eprintln!("vm {:?}", issue_options.verification_method);
        /*
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        */
        // Sign with proof suite directly because there is not currently a way to do it
        // for Eip712Signature2021 in did-pkh otherwise.
        let signer = SingleSecretSigner::new(key.clone()).into_local();
        eprintln!("key: {key}");
        eprintln!("suite: {proof_suite:?}");
        println!("cred: {}", serde_json::to_string_pretty(&cred).unwrap());
        let vc = proof_suite
            .sign(cred.clone(), &didpkh, &signer, issue_options.clone())
            .await
            .unwrap();
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // Test that issuer property is used for verification.
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(&params).await.unwrap().is_err());

        // Check that proof JWK must match proof verificationMethod
        let wrong_signer = SingleSecretSigner::new(wrong_key.clone()).into_local();
        let vc_wrong_key = proof_suite
            .sign(cred, &didpkh, &wrong_signer, issue_options)
            .await
            .unwrap();
        assert!(vc_wrong_key.verify(&params).await.unwrap().is_err());

        // Mess with proof signature to make verify fail.
        let mut vc_fuzzed = vc.clone();
        vc_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vc_fuzzed_result = vc_fuzzed.verify(&params).await;
        assert!(vc_fuzzed_result.is_err() || vc_fuzzed_result.is_ok_and(|v| v.is_err()));

        // Make it into a VP.
        let presentation = JsonPresentation::new(None, Some(did.clone().into()), vec![vc]);

        let vp_issue_options = ProofOptions::new(
            "2021-03-18T16:38:25Z".parse().unwrap(),
            IriBuf::new(did.to_string() + vm_relative_url)
                .unwrap()
                .into(),
            ProofPurpose::Authentication,
            AnyInputSuiteOptions {
                eip712: vp_eip712_domain_opt.clone(),
                ..Default::default()
            }
            .with_public_key(key.to_public())
            .unwrap(),
        );

        eprintln!(
            "presentation: {}",
            serde_json::to_string_pretty(&presentation).unwrap()
        );
        let vp = proof_suite
            .sign(presentation, &didpkh, &signer, vp_issue_options)
            .await
            .unwrap();

        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        assert!(vp.verify(&params).await.unwrap().is_ok());

        // Mess with proof signature to make verify fail.
        let mut vp_fuzzed = vp.clone();
        vp_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vp_fuzzed_result = vp_fuzzed.verify(&params).await;
        assert!(vp_fuzzed_result.is_err() || vp_fuzzed_result.is_ok_and(|v| v.is_err()));

        // Test that holder is verified.
        let mut vp_bad_holder = vp.clone();
        vp_bad_holder.holder = Some(uri!("did:pkh:example:bad").to_owned().into());

        // It should fail.
        assert!(vp_bad_holder.verify(&params).await.unwrap().is_err());
    }

    #[cfg(all(feature = "eip", feature = "tezos"))]
    async fn credential_prepare_complete_verify_did_pkh_tz(
        key: JWK,
        wrong_key: JWK,
        type_: &str,
        vm_relative_url: &str,
        proof_suite: ssi_claims::data_integrity::AnySuite,
    ) {
        use iref::IriBuf;
        use ssi_claims::{
            data_integrity::{
                signing::AlterSignature, AnyInputSuiteOptions, CryptographicSuite, ProofOptions,
            },
            vc::{
                syntax::NonEmptyVec,
                v1::{JsonCredential, JsonPresentation},
            },
            VerificationParameters,
        };
        use ssi_verification_methods_core::{ProofPurpose, SingleSecretSigner};
        use static_iref::uri;

        let didpkh = VerificationMethodDIDResolver::new(DIDPKH);
        let verifier = VerificationParameters::from_resolver(&didpkh);
        let did = DIDPKH::generate(&key, type_).unwrap();

        eprintln!("did: {}", did);
        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-03-18T16:38:25Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            })),
        );
        let issuance_date = cred.issuance_date.clone().unwrap();
        let created_date =
            xsd_types::DateTimeStamp::new(issuance_date.date_time, issuance_date.offset.unwrap());
        let issue_options = ProofOptions::new(
            created_date,
            IriBuf::new(did.to_string() + vm_relative_url)
                .unwrap()
                .into(),
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default()
                .with_public_key(key.to_public())
                .unwrap(),
        );
        eprintln!("vm {:?}", issue_options.verification_method);
        let signer = SingleSecretSigner::new(key.clone()).into_local();
        eprintln!("key: {key}");
        eprintln!("suite: {proof_suite:?}");
        let vc = proof_suite
            .sign(cred.clone(), &didpkh, &signer, issue_options.clone())
            .await
            .unwrap();
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        assert!(vc.verify(&verifier).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();
        assert!(!vc_bad_issuer.verify(&verifier).await.unwrap().is_ok());

        // Check that proof JWK must match proof verificationMethod.
        let wrong_signer = SingleSecretSigner::new(wrong_key.clone()).into_local();
        let vc_wrong_key = proof_suite
            .sign(cred, &didpkh, &wrong_signer, issue_options)
            .await
            .unwrap();
        assert!(vc_wrong_key.verify(&verifier).await.unwrap().is_err());

        // Mess with proof signature to make verify fail
        let mut vc_fuzzed = vc.clone();
        vc_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vc_fuzzed_result = vc_fuzzed.verify(&verifier).await;
        assert!(vc_fuzzed_result.is_err() || vc_fuzzed_result.is_ok_and(|v| v.is_err()));

        // Make it into a VP
        let presentation = JsonPresentation::new(None, Some(did.clone().into()), vec![vc]);

        let vp_issue_options = ProofOptions::new(
            "2021-03-18T16:38:25Z".parse().unwrap(),
            IriBuf::new(did.to_string() + vm_relative_url)
                .unwrap()
                .into(),
            ProofPurpose::Authentication,
            AnyInputSuiteOptions::default()
                .with_public_key(key.to_public())
                .unwrap(),
        );

        let vp = proof_suite
            .sign(presentation, &didpkh, &signer, vp_issue_options)
            .await
            .unwrap();

        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        assert!(vp.verify(&verifier).await.unwrap().is_ok());

        // Mess with proof signature to make verify fail.
        let mut vp_fuzzed = vp.clone();
        vp_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vp_fuzzed_result = vp_fuzzed.verify(&verifier).await;
        assert!(vp_fuzzed_result.is_err() || vp_fuzzed_result.is_ok_and(|v| v.is_err()));

        // Test that holder is verified.
        let mut vp_bad_holder = vp.clone();
        vp_bad_holder.holder = Some(uri!("did:pkh:example:bad").to_owned().into());
        // It should fail.
        assert!(vp_bad_holder.verify(&verifier).await.unwrap().is_err());
    }

    // fn sign_tezos(prep: &ssi_ldp::ProofPreparation, algorithm: Algorithm, key: &JWK) -> String {
    //     // Simulate signing with a Tezos wallet
    //     let micheline = match prep.signing_input {
    //         ssi_ldp::SigningInput::Micheline { ref micheline } => hex::decode(micheline).unwrap(),
    //         _ => panic!("Expected Micheline expression for signing"),
    //     };
    //     ssi_tzkey::sign_tezos(&micheline, algorithm, key).unwrap()
    // }

    #[tokio::test]
    #[cfg(all(feature = "eip", feature = "tezos"))]
    async fn resolve_vc_issue_verify() {
        use serde_json::json;
        use ssi_claims::data_integrity::AnySuite;
        use ssi_jwk::Algorithm;

        let key_secp256k1: JWK = serde_json::from_str(include_str!(
            "../../../../../tests/secp256k1-2021-02-17.json"
        ))
        .unwrap();
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
            serde_json::from_str(include_str!("../../../../../tests/ed25519-2020-10-18.json"))
                .unwrap();
        let mut key_p256: JWK = serde_json::from_str(include_str!(
            "../../../../../tests/secp256r1-2021-03-18.json"
        ))
        .unwrap();
        let other_key_secp256k1 = JWK::generate_secp256k1();
        let mut other_key_ed25519 = JWK::generate_ed25519().unwrap();
        let mut other_key_p256 = JWK::generate_p256();

        // eth/Recovery2020
        credential_prove_verify_did_pkh(
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "eip155",
            "#blockchainAccountId",
            AnySuite::EcdsaSecp256k1RecoverySignature2020,
            None,
            None,
        )
        .await;

        // eth/Eip712
        credential_prove_verify_did_pkh(
            key_secp256k1_eip712sig.clone(),
            other_key_secp256k1.clone(),
            "eip155",
            "#blockchainAccountId",
            AnySuite::Eip712Signature2021,
            None,
            None,
        )
        .await;

        // eth/epsig
        credential_prove_verify_did_pkh(
            key_secp256k1_eip712sig.clone(),
            other_key_secp256k1.clone(),
            "eip155",
            "#blockchainAccountId",
            AnySuite::EthereumPersonalSignature2021,
            None,
            None,
        )
        .await;

        // eth/Eip712
        let eip712_domain = serde_json::from_value(json!({
          "types": {
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
        let vp_eip712_domain = serde_json::from_value(json!({
          "types": {
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
              { "name": "eip712", "type": "EIP712Info" },
              { "name": "type", "type": "string" }
            ],
            "EIP712Info": [
              { "name": "domain", "type": "EIP712Domain" },
              { "name": "primaryType", "type": "string" },
              { "name": "types", "type": "Types" },
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
            "eip155",
            "#blockchainAccountId",
            AnySuite::EthereumEip712Signature2021,
            Some(eip712_domain),
            Some(vp_eip712_domain),
        )
        .await;

        // eth/Eip712
        credential_prove_verify_did_pkh(
            key_secp256k1_epsig.clone(),
            other_key_secp256k1.clone(),
            "eip155",
            "#blockchainAccountId",
            AnySuite::Eip712Signature2021,
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
            AnySuite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
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
        //     &ssi_ldp::EcdsaSecp256k1RecoverySignature2020,
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
            AnySuite::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
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
            AnySuite::Ed25519Signature2018,
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
            &ssi_ldp::SolanaSignature2021,
        )
        .await;
        */

        println!("did:pkh:btc");
        credential_prove_verify_did_pkh(
            key_secp256k1_recovery.clone(),
            other_key_secp256k1.clone(),
            "btc",
            "#blockchainAccountId",
            AnySuite::EcdsaSecp256k1RecoverySignature2020,
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
            AnySuite::EcdsaSecp256k1RecoverySignature2020,
            None,
            None,
        )
        .await;

        println!("did:pkh:tz:tz1 - TezosMethod2021");
        key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        other_key_ed25519.algorithm = Some(Algorithm::EdBlake2b);
        credential_prepare_complete_verify_did_pkh_tz(
            key_ed25519.clone(),
            other_key_ed25519.clone(),
            "tz",
            "#TezosMethod2021",
            AnySuite::TezosSignature2021,
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
            &ssi_ldp::TezosSignature2021,
        )
        .await;
        */

        println!("did:pkh:tz:tz3 - TezosMethod2021");
        key_p256.algorithm = Some(Algorithm::ESBlake2b);
        other_key_p256.algorithm = Some(Algorithm::ESBlake2b);
        credential_prepare_complete_verify_did_pkh_tz(
            key_p256.clone(),
            other_key_p256.clone(),
            "tz",
            "#TezosMethod2021",
            AnySuite::TezosSignature2021,
        )
        .await;
        key_p256.algorithm = Some(Algorithm::ES256);
        other_key_p256.algorithm = Some(Algorithm::ES256);
    }

    async fn test_verify_vc(name: &str, vc_str: &str, _num_warnings: usize) {
        // TODO check warnings maybe?
        eprintln!("test verify vc `{name}`");
        eprintln!("input: {vc_str}");

        let vc = ssi_claims::vc::v1::data_integrity::any_credential_from_json_str(vc_str).unwrap();

        let didpkh = VerificationMethodDIDResolver::new(DIDPKH);
        let verifier = VerificationParameters::from_resolver(&didpkh);
        let verification_result = vc.verify(&verifier).await.unwrap();
        assert!(verification_result.is_ok());

        // // assert_eq!(verification_result.warnings.len(), num_warnings); // TODO warnings

        // Negative test: tamper with the VC and watch verification fail.
        let mut bad_vc = vc.clone();
        bad_vc
            .additional_properties
            .insert("http://example.org/foo".into(), "bar".into());
        for proof in &mut bad_vc.proofs {
            // Add the `foo` field to the EIP712 VC schema if necessary.
            // This is required so hashing can succeed.
            if let Some(eip712) = proof.options.eip712_mut() {
                if let Some(ssi_claims::data_integrity::suites::eip712::TypesOrURI::Object(types)) =
                    &mut eip712.types
                {
                    let vc_schema = types.types.get_mut("VerifiableCredential").unwrap();
                    vc_schema.push(ssi_eip712::MemberVariable::new(
                        "http://example.org/foo".to_owned(),
                        ssi_eip712::TypeRef::String,
                    ));
                }
            }

            // Same as above but for the legacy EIP712 cryptosuite (v0.1).
            if let Some(eip712) = proof.options.eip712_v0_1_mut() {
                if let Some(ssi_claims::data_integrity::suites::eip712::TypesOrURI::Object(types)) =
                    &mut eip712.message_schema
                {
                    let vc_schema = types.types.get_mut("VerifiableCredential").unwrap();
                    vc_schema.push(ssi_eip712::MemberVariable::new(
                        "http://example.org/foo".to_owned(),
                        ssi_eip712::TypeRef::String,
                    ));
                }
            }
        }

        let verification_result = bad_vc.verify(verifier).await.unwrap();
        assert!(verification_result.is_err());
    }

    #[tokio::test]
    async fn verify_vc() {
        // TODO: update these to use CAIP-10 did:pkh issuers
        test_verify_vc("vc-tz1", include_str!("../tests/vc-tz1.jsonld"), 0).await;
        test_verify_vc(
            "vc-tz1-jcs.jsonld",
            include_str!("../tests/vc-tz1-jcs.jsonld"),
            1,
        )
        .await;
        // TODO: either remove or update this test that uses an older version of
        // the `EthereumEip712Signature2021` suite.
        // test_verify_vc(
        //     "vc-eth-eip712sig.jsonld",
        //     include_str!("../tests/vc-eth-eip712sig.jsonld"),
        //     0,
        // )
        // .await;
        test_verify_vc(
            "vc-eth-eip712vm",
            include_str!("../tests/vc-eth-eip712vm.jsonld"),
            0,
        )
        .await;
        test_verify_vc(
            "vc-eth-epsig",
            include_str!("../tests/vc-eth-epsig.jsonld"),
            0,
        )
        .await;
        test_verify_vc(
            "vc-celo-epsig",
            include_str!("../tests/vc-celo-epsig.jsonld"),
            0,
        )
        .await;
        test_verify_vc(
            "vc-poly-epsig",
            include_str!("../tests/vc-poly-epsig.jsonld"),
            0,
        )
        .await;
        test_verify_vc(
            "vc-poly-eip712sig",
            include_str!("../tests/vc-poly-eip712sig.jsonld"),
            0,
        )
        .await;
    }
}
