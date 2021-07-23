use std::collections::HashMap as Map;
#[cfg(feature = "keccak-hash")]
use std::convert::TryFrom;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::prelude::*;

const EDPK_PREFIX: [u8; 4] = [13, 15, 37, 217];
const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];

// use crate::did::{VerificationMethod, VerificationMethodMap};
use crate::caip10::BlockchainAccountId;
use crate::did::{Resource, VerificationMethodMap};
use crate::did_resolve::{dereference, Content, DIDResolver, DereferencingInputMetadata};
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedData;
use crate::error::Error;
use crate::hash::sha256;
use crate::jwk::Base64urlUInt;
use crate::jwk::{Algorithm, OctetParams as JWKOctetParams, Params as JWKParams, JWK};
use crate::jws::Header;
use crate::rdf::DataSet;
use crate::urdna2015;
use crate::vc::{LinkedDataProofOptions, Proof, URI};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// TODO: factor out proof types
lazy_static! {
    /// JSON-LD context for Linked Data Proofs based on Tezos addresses
    pub static ref TZ_CONTEXT: Value = {
        let context_str = ssi_contexts::TZ_V2;
        serde_json::from_str(&context_str).unwrap()
    };
    pub static ref TZVM_CONTEXT: Value = {
        let context_str = ssi_contexts::TZVM_V1;
        serde_json::from_str(&context_str).unwrap()
    };
    pub static ref EIP712VM_CONTEXT: Value = {
        let context_str = ssi_contexts::EIP712VM;
        serde_json::from_str(&context_str).unwrap()
    };
    pub static ref EPSIG_CONTEXT: Value = {
        let context_str = ssi_contexts::EPSIG_V0_1;
        serde_json::from_str(&context_str).unwrap()
    };
    pub static ref SOLVM_CONTEXT: Value = {
        let context_str = ssi_contexts::SOLVM;
        serde_json::from_str(&context_str).unwrap()
    };
}

pub fn get_proof_suite(proof_type: &str) -> Result<&(dyn ProofSuite + Sync), Error> {
    Ok(match proof_type {
        "RsaSignature2018" => &RsaSignature2018,
        "Ed25519Signature2018" => &Ed25519Signature2018,
        "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
            &Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        }
        "P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
            &P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        }
        "EcdsaSecp256k1Signature2019" => &EcdsaSecp256k1Signature2019,
        "EcdsaSecp256k1RecoverySignature2020" => &EcdsaSecp256k1RecoverySignature2020,
        #[cfg(feature = "keccak-hash")]
        "Eip712Signature2021" => &Eip712Signature2021,
        #[cfg(feature = "keccak-hash")]
        "EthereumPersonalSignature2021" => &EthereumPersonalSignature2021,
        #[cfg(feature = "keccak-hash")]
        "EthereumEip712Signature2021" => &EthereumEip712Signature2021,
        "TezosSignature2021" => &TezosSignature2021,
        "SolanaSignature2021" => &SolanaSignature2021,
        "JsonWebSignature2020" => &JsonWebSignature2020,
        "EcdsaSecp256r1Signature2019" => &EcdsaSecp256r1Signature2019,
        _ => return Err(Error::ProofTypeNotImplemented),
    })
}

fn pick_proof_suite<'a, 'b>(
    jwk: &JWK,
    verification_method: Option<&'a URI>,
) -> Result<&'b (dyn ProofSuite + Sync), Error> {
    let algorithm = jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?;
    Ok(match algorithm {
        Algorithm::RS256 => &RsaSignature2018,

        Algorithm::EdDSA => match verification_method {
            Some(URI::String(ref vm)) if vm.ends_with("#SolanaMethod2021") => &SolanaSignature2021,
            _ => &Ed25519Signature2018,
        },
        Algorithm::EdBlake2b => match verification_method {
            Some(URI::String(ref vm))
                if (vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:"))
                    && vm.ends_with("#TezosMethod2021") =>
            {
                &TezosSignature2021
            }
            _ => &Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
        },
        Algorithm::ES256 => &EcdsaSecp256r1Signature2019,
        Algorithm::ESBlake2b => match verification_method {
            Some(URI::String(ref vm))
                if (vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:"))
                    && vm.ends_with("#TezosMethod2021") =>
            {
                &TezosSignature2021
            }
            _ => &P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
        },
        Algorithm::ES256K => &EcdsaSecp256k1Signature2019,
        Algorithm::ESBlake2bK => match verification_method {
            Some(URI::String(ref vm))
                if (vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:"))
                    && vm.ends_with("#TezosMethod2021") =>
            {
                &TezosSignature2021
            }
            _ => &EcdsaSecp256k1RecoverySignature2020,
        },
        Algorithm::ES256KR => {
            if use_eip712sig(jwk) {
                #[cfg(not(feature = "keccak-hash"))]
                return Err(Error::ProofTypeNotImplemented);
                &EthereumEip712Signature2021
            } else if use_epsig(jwk) {
                #[cfg(not(feature = "keccak-hash"))]
                return Err(Error::ProofTypeNotImplemented);
                &EthereumPersonalSignature2021
            } else {
                match verification_method {
                    Some(URI::String(ref vm))
                        if (vm.starts_with("did:ethr:") || vm.starts_with("did:pkh:eth:"))
                            && vm.ends_with("#Eip712Method2021") =>
                    {
                        #[cfg(not(feature = "keccak-hash"))]
                        return Err(Error::ProofTypeNotImplemented);
                        &Eip712Signature2021
                    }
                    _ => &EcdsaSecp256k1RecoverySignature2020,
                }
            }
        }
        _ => return Err(Error::ProofTypeNotImplemented),
    })
}

// Get current time to millisecond precision if possible
pub fn now_ms() -> DateTime<Utc> {
    let datetime = Utc::now();
    let ms = datetime.timestamp_subsec_millis();
    let ns = ms * 1_000_000;
    datetime.with_nanosecond(ns).unwrap_or(datetime)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait LinkedDataDocument {
    fn get_contexts(&self) -> Result<Option<String>, Error>;
    fn to_value(&self) -> Result<Value, Error>;
    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ProofSuite {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error>;

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error>;

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error>;

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofPreparation {
    pub proof: Proof,
    pub jws_header: Option<Header>,
    pub signing_input: SigningInput,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SigningInput {
    Bytes(Base64urlUInt),
    #[cfg(feature = "keccak-hash")]
    TypedData(TypedData),
    #[serde(rename_all = "camelCase")]
    EthereumPersonalMessage {
        ethereum_personal_message: String,
    },
    Micheline {
        micheline: String,
    },
}

impl ProofPreparation {
    pub async fn complete(self, signature: &str) -> Result<Proof, Error> {
        let proof_type = self.proof.type_.clone();
        let suite = get_proof_suite(&proof_type)?;
        suite.complete(self, signature).await
    }
}

fn use_eip712sig(key: &JWK) -> bool {
    // Use unregistered "signTypedData" key operation value to indicate using EthereumEip712Signature2021, until
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signTypedData".to_string()) {
            return true;
        }
    }
    return false;
}

fn use_eip712vm(options: &LinkedDataProofOptions) -> bool {
    if let Some(URI::String(ref vm)) = options.verification_method {
        if vm.ends_with("#Eip712Method2021") {
            return true;
        }
    }
    return false;
}

fn use_epsig(key: &JWK) -> bool {
    // Use unregistered "signPersonalMessage" key operation value to indicate using EthereumPersonalSignature2021, until
    // LinkedDataProofOptions has type property
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signPersonalMessage".to_string()) {
            return true;
        }
    }
    return false;
}

pub struct LinkedDataProofs;
impl LinkedDataProofs {
    // https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
    pub async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        // Use type property if present
        let suite = if let Some(ref type_) = options.type_ {
            get_proof_suite(type_)?
        }
        // Otherwise pick proof type based on key and options.
        else {
            pick_proof_suite(key, options.verification_method.as_ref())?
        };
        suite
            .sign(document, options, &key, extra_proof_properties)
            .await
    }

    /// Prepare to create a linked data proof. Given a linked data document, proof options, and JWS
    /// algorithm, calculate the signing input bytes. Returns a [`ProofPreparation`] - the data for the caller to sign, along with data to reconstruct the proof.
    pub async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        // Use type property if present
        let suite = if let Some(ref type_) = options.type_ {
            get_proof_suite(type_)?
        }
        // Otherwise pick proof type based on key and options.
        else {
            pick_proof_suite(public_key, options.verification_method.as_ref())?
        };
        suite
            .prepare(document, options, public_key, extra_proof_properties)
            .await
    }

    // https://w3c-ccg.github.io/ld-proofs/#proof-verification-algorithm
    pub async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let suite = get_proof_suite(proof.type_.as_str())?;
        suite.verify(proof, document, resolver).await
    }
}

/// Resolve a verificationMethod to a key
pub async fn resolve_key(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<JWK, Error> {
    let vm = resolve_vm(verification_method, resolver).await?;
    if let Some(pk_jwk) = vm.public_key_jwk {
        if vm.public_key_base58.is_some() {
            // https://w3c.github.io/did-core/#verification-material
            // "expressing key material in a verification method using both publicKeyJwk and
            // publicKeyBase58 at the same time is prohibited."
            return Err(Error::MultipleKeyMaterial);
        }
        return Ok(pk_jwk);
    }
    if let Some(pk_bs58) = vm.public_key_base58 {
        return jwk_from_public_key_base58(&pk_bs58, &vm.type_);
    }
    Err(Error::MissingKey)
}

fn jwk_from_public_key_base58(pk_bs58: &str, vm_type: &str) -> Result<JWK, Error> {
    let pk_bytes = bs58::decode(&pk_bs58).into_vec()?;
    let params = match vm_type {
        "Ed25519VerificationKey2018" => JWKParams::OKP(JWKOctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(pk_bytes),
            private_key: None,
        }),
        _ => return Err(Error::UnsupportedKeyType),
    };
    let jwk = JWK {
        params,
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    Ok(jwk)
}

/// Resolve a verificationMethod
pub async fn resolve_vm(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<VerificationMethodMap, Error> {
    let (res_meta, object, _meta) = dereference(
        resolver,
        &verification_method,
        &DereferencingInputMetadata::default(),
    )
    .await;
    if let Some(error) = res_meta.error {
        return Err(Error::DIDURLDereference(error));
    }
    let vm = match object {
        Content::Object(Resource::VerificationMethod(vm)) => vm,
        Content::Null => return Err(Error::ResourceNotFound(verification_method.to_string())),
        _ => return Err(Error::ExpectedObject),
    };
    Ok(vm)
}

async fn to_jws_payload(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let sigopts_digest = sha256(sigopts_normalized.as_bytes())?;
    let doc_digest = sha256(doc_normalized.as_bytes())?;
    let data = [
        sigopts_digest.as_ref().to_vec(),
        doc_digest.as_ref().to_vec(),
    ]
    .concat();
    Ok(data)
}

async fn sign(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<Proof, Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    sign_proof(document, proof, key, algorithm).await
}

async fn sign_proof(
    document: &(dyn LinkedDataDocument + Sync),
    mut proof: Proof,
    key: &JWK,
    algorithm: Algorithm,
) -> Result<Proof, Error> {
    let message = to_jws_payload(document, &proof).await?;
    let jws = crate::jws::detached_sign_unencoded_payload(algorithm, &message, &key)?;
    proof.jws = Some(jws);
    Ok(proof)
}

async fn prepare(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    public_key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<ProofPreparation, Error> {
    if let Some(key_algorithm) = public_key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    prepare_proof(document, proof, algorithm).await
}

async fn prepare_proof(
    document: &(dyn LinkedDataDocument + Sync),
    proof: Proof,
    algorithm: Algorithm,
) -> Result<ProofPreparation, Error> {
    let message = to_jws_payload(document, &proof).await?;
    let (jws_header, signing_input) =
        crate::jws::prepare_detached_unencoded_payload(algorithm, &message)?;
    Ok(ProofPreparation {
        proof,
        jws_header: Some(jws_header),
        signing_input: SigningInput::Bytes(Base64urlUInt(signing_input)),
    })
}

async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
    complete_proof(preparation, signature).await
}

async fn complete_proof(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
    let mut proof = preparation.proof;
    let jws_header = preparation.jws_header.ok_or(Error::MissingJWSHeader)?;
    let jws = crate::jws::complete_sign_unencoded_payload(jws_header, signature)?;
    proof.jws = Some(jws);
    Ok(proof)
}

async fn verify(
    proof: &Proof,
    document: &(dyn LinkedDataDocument + Sync),
    resolver: &dyn DIDResolver,
) -> Result<(), Error> {
    let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
    let verification_method = proof
        .verification_method
        .as_ref()
        .ok_or(Error::MissingVerificationMethod)?;
    let key = resolve_key(&verification_method, resolver).await?;
    let message = to_jws_payload(document, proof).await?;
    crate::jws::detached_verify(&jws, &message, &key)?;
    Ok(())
}

pub struct RsaSignature2018;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for RsaSignature2018 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "RsaSignature2018",
            Algorithm::RS256,
            extra_proof_properties,
        )
        .await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "RsaSignature2018",
            Algorithm::RS256,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct Ed25519Signature2018;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for Ed25519Signature2018 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "Ed25519Signature2018",
            Algorithm::EdDSA,
            extra_proof_properties,
        )
        .await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "Ed25519Signature2018",
            Algorithm::EdDSA,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct EcdsaSecp256k1Signature2019;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for EcdsaSecp256k1Signature2019 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "EcdsaSecp256k1Signature2019",
            Algorithm::ES256K,
            extra_proof_properties,
        )
        .await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "EcdsaSecp256k1Signature2019",
            Algorithm::ES256K,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct EcdsaSecp256k1RecoverySignature2020;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for EcdsaSecp256k1RecoverySignature2020 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::ES256KR {
                return Err(Error::AlgorithmMismatch);
            }
        }
        let proof = Proof {
            context: serde_json::json!([
                crate::jsonld::DIF_ESRS2020_CONTEXT,
                crate::jsonld::ESRS2020_EXTRA_CONTEXT,
            ]),
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, Algorithm::ES256KR).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([
                crate::jsonld::DIF_ESRS2020_CONTEXT,
                crate::jsonld::ESRS2020_EXTRA_CONTEXT,
            ]),
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, Algorithm::ES256KR).await
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        if vm.type_ != "EcdsaSecp256k1RecoveryMethod2020" {
            return Err(Error::VerificationMethodMismatch);
        }
        let message = to_jws_payload(document, proof).await?;
        let (_header, jwk) = crate::jws::detached_recover(&jws, &message)?;
        let account_id_str = vm.blockchain_account_id.ok_or(Error::MissingAccountId)?;
        let account_id = BlockchainAccountId::from_str(&account_id_str)?;
        account_id.verify(&jwk)?;
        Ok(())
    }
}

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::EdBlake2b {
                return Err(Error::AlgorithmMismatch);
            }
        }
        let jwk_value = serde_json::to_value(key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);

        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::EdBlake2b).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let jwk_value = serde_json::to_value(public_key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);
        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::EdBlake2b).await
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let jwk: JWK = match proof.property_set {
            Some(ref props) => {
                let jwk_value = props.get("publicKeyJwk").ok_or(Error::MissingKey)?;
                serde_json::from_value(jwk_value.clone())?
            }
            None => return Err(Error::MissingKey),
        };
        // Ensure the verificationMethod corresponds to the hashed public key.
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        let account_id: BlockchainAccountId = vm
            .blockchain_account_id
            .ok_or(Error::MissingAccountId)?
            .parse()?;
        account_id.verify(&jwk)?;
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(&jws, &message, &jwk)?;
        Ok(())
    }
}

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz3` addresses.
pub struct P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::ESBlake2b {
                return Err(Error::AlgorithmMismatch);
            }
        }
        let jwk_value = serde_json::to_value(key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);
        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            ..Proof::new("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::ESBlake2b).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let jwk_value = serde_json::to_value(public_key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);
        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            ..Proof::new("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::ESBlake2b).await
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let jwk: JWK = match proof.property_set {
            Some(ref props) => {
                let jwk_value = props.get("publicKeyJwk").ok_or(Error::MissingKey)?;
                serde_json::from_value(jwk_value.clone())?
            }
            None => return Err(Error::MissingKey),
        };
        // Ensure the verificationMethod corresponds to the hashed public key.
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        let account_id: BlockchainAccountId = vm
            .blockchain_account_id
            .ok_or(Error::MissingAccountId)?
            .parse()?;
        account_id.verify(&jwk)?;
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(&jws, &message, &jwk)?;
        Ok(())
    }
}

#[cfg(feature = "keccak-hash")]
pub struct Eip712Signature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(feature = "keccak-hash")]
impl ProofSuite for Eip712Signature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        use k256::ecdsa::signature::Signer;
        let mut proof = Proof {
            context: serde_json::json!([EIP712VM_CONTEXT.clone()]),
            ..Proof::new("Eip712Signature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let typed_data = TypedData::from_document_and_options(document, &proof).await?;
        let bytes = typed_data.bytes()?;
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(Error::KeyTypeNotImplemented),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature = signing_key.try_sign(&bytes)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] = sig_bytes[64] + 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EIP712VM_CONTEXT.clone()]),
            ..Proof::new("Eip712Signature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let typed_data = TypedData::from_document_and_options(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::TypedData(typed_data),
        })
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        match &vm.type_[..] {
            "Eip712Method2021" => (),
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => Err(Error::VerificationMethodMismatch)?,
        };
        let typed_data = TypedData::from_document_and_options(document, &proof).await?;
        let bytes = typed_data.bytes()?;
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] - 27)?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)?;
        // TODO this step needs keccak-hash, may need better features management
        let recovered_key = sig.recover_verify_key(&bytes)?;
        use crate::jwk::ECParams;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(&k256::PublicKey::from_sec1_bytes(
                &recovered_key.to_bytes(),
            )?)?),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let account_id_str = vm.blockchain_account_id.ok_or(Error::MissingAccountId)?;
        let account_id = BlockchainAccountId::from_str(&account_id_str)?;
        account_id.verify(&jwk)?;
        Ok(())
    }
}

#[cfg(feature = "keccak-hash")]
pub struct EthereumEip712Signature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(feature = "keccak-hash")]
impl ProofSuite for EthereumEip712Signature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        use k256::ecdsa::signature::Signer;
        // TODO: conform to spec: no domain
        let mut props = extra_proof_properties.clone();
        if let Some(ref eip712_domain) = options.eip712_domain {
            let info = serde_json::to_value(eip712_domain.clone())?;
            props
                .get_or_insert(Map::new())
                .insert("eip712Domain".to_string(), info);
        }
        let mut proof = Proof {
            context: serde_json::json!(crate::jsonld::EIP712SIG_V0_1_CONTEXT),
            ..Proof::new("EthereumEip712Signature2021")
                .with_options(options)
                .with_properties(props)
        };
        let typed_data = TypedData::from_document_and_options_json(document, &proof).await?;
        let bytes = typed_data.bytes()?;
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(Error::KeyTypeNotImplemented),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature = signing_key.try_sign(&bytes)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] = sig_bytes[64] + 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let mut props = extra_proof_properties.clone();
        if let Some(ref eip712_domain) = options.eip712_domain {
            let info = serde_json::to_value(eip712_domain.clone())?;
            props
                .get_or_insert(Map::new())
                .insert("eip712Domain".to_string(), info);
        }
        let proof = Proof {
            context: serde_json::json!(crate::jsonld::EIP712SIG_V0_1_CONTEXT),
            ..Proof::new("EthereumEip712Signature2021")
                .with_options(options)
                .with_properties(props)
        };
        let typed_data = TypedData::from_document_and_options_json(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::TypedData(typed_data),
        })
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        match &vm.type_[..] {
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => Err(Error::VerificationMethodMismatch)?,
        };
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] - 27)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)?;
        let typed_data = TypedData::from_document_and_options_json(document, &proof).await?;
        let bytes = typed_data.bytes()?;
        let recovered_key = sig.recover_verify_key(&bytes)?;
        use crate::jwk::ECParams;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(&k256::PublicKey::from_sec1_bytes(
                &recovered_key.to_bytes(),
            )?)?),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        // Verify using eiher publicKeyJwk or blockchainAccountId.
        if let Some(vm_jwk) = vm.public_key_jwk {
            // If VM has publicKey, use that to veify the signature.
            let mut dec_sig = dec_sig;
            dec_sig[64] -= 27;
            crate::jws::verify_bytes(Algorithm::ES256KR, &bytes, &vm_jwk, &dec_sig)?;
        } else {
            let account_id_str = vm.blockchain_account_id.ok_or(Error::MissingAccountId)?;
            let account_id = BlockchainAccountId::from_str(&account_id_str)?;
            account_id.verify(&jwk)?;
        }
        Ok(())
    }
}

#[cfg(feature = "keccak-hash")]
pub struct EthereumPersonalSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(feature = "keccak-hash")]
impl ProofSuite for EthereumPersonalSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        use crate::passthrough_digest::PassthroughDigest;
        use k256::ecdsa::signature::{digest::Digest, DigestSigner};
        let mut proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new("EthereumPersonalSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let signing_string = string_from_document_and_options(document, &proof).await?;
        let hash = crate::keccak_hash::hash_personal_message(&signing_string);
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(Error::KeyTypeNotImplemented),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let digest = Digest::chain(<PassthroughDigest as Digest>::new(), &hash);
        let sig: k256::ecdsa::recoverable::Signature = signing_key.try_sign_digest(digest)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] = sig_bytes[64] + 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new("EthereumPersonalSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let signing_string = string_from_document_and_options(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::EthereumPersonalMessage {
                ethereum_personal_message: signing_string,
            },
        })
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        match &vm.type_[..] {
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => Err(Error::VerificationMethodMismatch)?,
        };
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] - 27)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)?;
        let signing_string = string_from_document_and_options(document, &proof).await?;
        let hash = crate::keccak_hash::hash_personal_message(&signing_string);
        let digest = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::from_slice(&hash);
        let recovered_key = sig.recover_verify_key_from_digest_bytes(&digest)?;
        use crate::jwk::ECParams;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(&k256::PublicKey::from_sec1_bytes(
                &recovered_key.to_bytes(),
            )?)?),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let account_id_str = vm.blockchain_account_id.ok_or(Error::MissingAccountId)?;
        let account_id = BlockchainAccountId::from_str(&account_id_str)?;
        account_id.verify(&jwk)?;
        Ok(())
    }
}

async fn micheline_from_document_and_options(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let msg = ["", &sigopts_normalized, &doc_normalized].join("\n");
    let data = crate::tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

async fn string_from_document_and_options(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<String, Error> {
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let msg = sigopts_normalized + "\n" + &doc_normalized;
    Ok(msg)
}

pub struct TezosSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for TezosSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        let jwk_value = serde_json::to_value(key.to_public())?;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);
        let mut proof = Proof {
            context: TZVM_CONTEXT.clone(),
            ..Proof::new("TezosSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        let micheline = micheline_from_document_and_options(document, &proof).await?;
        let sig = crate::jws::sign_bytes(algorithm, &micheline, key)?;
        let mut sig_prefixed = Vec::new();
        let prefix: &[u8] = match algorithm {
            Algorithm::EdBlake2b => &EDSIG_PREFIX,
            Algorithm::ESBlake2bK => &SPSIG_PREFIX,
            Algorithm::ESBlake2b => &P2SIG_PREFIX,
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        sig_prefixed.extend_from_slice(&prefix);
        sig_prefixed.extend_from_slice(&sig);
        let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
        proof.proof_value = Some(sig_bs58);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        // TODO: dereference VM URL to check if VM already contains public key.
        let jwk_value = serde_json::to_value(public_key.to_public())?;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyJwk".to_string(), jwk_value);

        let proof = Proof {
            context: TZVM_CONTEXT.clone(),
            ..Proof::new("TezosSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        let micheline = micheline_from_document_and_options(document, &proof).await?;
        let micheline_string = hex::encode(micheline);
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Micheline {
                micheline: micheline_string,
            },
        })
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let sig_bs58 = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let proof_jwk_opt: Option<JWK> = match proof.property_set {
            Some(ref props) => match props.get("publicKeyJwk") {
                Some(jwk_value) => serde_json::from_value(jwk_value.clone())?,
                None => None,
            },
            None => None,
        };

        let (algorithm, sig) = crate::tzkey::decode_tzsig(sig_bs58)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        if vm.type_ != "TezosMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }

        let micheline = micheline_from_document_and_options(document, &proof).await?;
        let account_id_opt: Option<BlockchainAccountId> = match vm.blockchain_account_id {
            Some(account_id_string) => Some(account_id_string.parse()?),
            None => None,
        };

        // VM must have either publicKeyJwk or blockchainAccountId.
        if let Some(vm_jwk) = vm.public_key_jwk {
            // If VM has publicKey, use that to veify the signature.
            crate::jws::verify_bytes(algorithm, &micheline, &vm_jwk, &sig)?;
            // Note: VM blockchainAccountId is ignored in this case.
        } else {
            if let Some(account_id) = account_id_opt {
                // VM does not have publicKeyJwk: proof must have public key
                if let Some(proof_jwk) = proof_jwk_opt {
                    // Proof has public key: verify it with blockchainAccountId,
                    account_id.verify(&proof_jwk)?;
                    // and verify the signature.
                    crate::jws::verify_bytes(algorithm, &micheline, &proof_jwk, &sig)?;
                } else {
                    return Err(Error::MissingKey);
                }
            } else {
                return Err(Error::MissingKey);
            }
        };
        Ok(())
    }
}

pub struct SolanaSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for SolanaSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let mut proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("SolanaSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let sig = crate::jws::sign_bytes(Algorithm::EdDSA, &bytes, key)?;
        let sig_b58 = bs58::encode(&sig).into_string();
        proof.proof_value = Some(sig_b58);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("SolanaSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(bytes)),
        })
    }

    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let sig_b58 = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(&verification_method, resolver).await?;
        if vm.type_ != "SolanaMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }
        let key = vm.public_key_jwk.ok_or(Error::MissingKey)?;
        let message = to_jws_payload(document, &proof).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let sig = bs58::decode(&sig_b58).into_vec()?;
        crate::jws::verify_bytes(Algorithm::EdDSA, &bytes, &key, &sig)?;
        Ok(())
    }
}

pub struct EcdsaSecp256r1Signature2019;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for EcdsaSecp256r1Signature2019 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "EcdsaSecp256r1Signature2019",
            Algorithm::ES256,
            extra_proof_properties,
        )
        .await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "EcdsaSecp256r1Signature2019",
            Algorithm::ES256,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

/// <https://w3c-ccg.github.io/lds-jws2020/>
pub struct JsonWebSignature2020;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for JsonWebSignature2020 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if algorithm != Algorithm::ES256 {
            // TODO: support JsonWebSignature2020 more generally
            return Err(Error::UnsupportedAlgorithm)?;
        }
        let proof = Proof {
            context: serde_json::json!([crate::jsonld::LDS_JWS2020_V1_CONTEXT.clone()]),
            ..Proof::new("JsonWebSignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, algorithm).await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let algorithm = public_key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if algorithm != Algorithm::ES256 {
            return Err(Error::UnsupportedAlgorithm)?;
        }
        let proof = Proof {
            context: serde_json::json!([crate::jsonld::LDS_JWS2020_V1_CONTEXT.clone()]),
            ..Proof::new("JsonWebSignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, algorithm).await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonld::CREDENTIALS_V1_CONTEXT;

    struct ExampleDocument;

    #[async_trait]
    impl LinkedDataDocument for ExampleDocument {
        fn get_contexts(&self) -> Result<Option<String>, Error> {
            Ok(Some(serde_json::to_string(&*CREDENTIALS_V1_CONTEXT)?))
        }
        async fn to_dataset_for_signing(
            &self,
            _parent: Option<&(dyn LinkedDataDocument + Sync)>,
        ) -> Result<DataSet, Error> {
            use crate::rdf;
            let mut dataset = DataSet::default();
            let statement = rdf::Statement {
                subject: rdf::Subject::BlankNodeLabel(rdf::BlankNodeLabel("_:c14n0".to_string())),
                predicate: rdf::Predicate::IRIRef(rdf::IRIRef(
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
                )),
                object: rdf::Object::IRIRef(rdf::IRIRef(
                    "http://example.org/vocab#Foo".to_string(),
                )),
                graph_label: None,
            };
            dataset.add_statement(statement);
            Ok(dataset)
        }

        fn to_value(&self) -> Result<Value, Error> {
            Err(Error::NotImplemented)
        }
    }

    #[cfg(feature = "secp256k1")]
    #[async_std::test]
    async fn eip712vm() {
        let mut key = JWK::generate_secp256k1().unwrap();
        key.algorithm = Some(Algorithm::ES256KR);
        let vm = format!("{}#Recovery2020", "did:example:foo");
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(vm)),
            ..Default::default()
        };
        let doc = ExampleDocument;
        let _proof = LinkedDataProofs::sign(&doc, &issue_options, &key, None)
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn tezos_vm_tz1() {
        let mut key = JWK::generate_ed25519().unwrap();
        key.algorithm = Some(Algorithm::EdBlake2b);
        let vm = format!("{}#TezosMethod2021", "did:example:foo");
        let issue_options = LinkedDataProofOptions {
            type_: Some(String::from("TezosSignature2021")),
            verification_method: Some(URI::String(vm)),
            ..Default::default()
        };
        let doc = ExampleDocument;
        let proof = LinkedDataProofs::sign(&doc, &issue_options, &key, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&proof).unwrap());
        // TODO: verify
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn tezos_vm_tz2() {
        let mut key = JWK::generate_secp256k1().unwrap();
        key.algorithm = Some(Algorithm::ESBlake2bK);
        let vm = format!("{}#TezosMethod2021", "did:example:foo");
        let issue_options = LinkedDataProofOptions {
            type_: Some(String::from("TezosSignature2021")),
            verification_method: Some(URI::String(vm)),
            ..Default::default()
        };
        let doc = ExampleDocument;
        let proof = LinkedDataProofs::sign(&doc, &issue_options, &key, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&proof).unwrap());
    }

    /*
    #[async_std::test]
    async fn solvm() {
        let mut key = JWK::generate_secp256k1().unwrap();
        key.algorithm = Some(Algorithm::ES256KR);
        let vm = format!("{}#SolanaMethod2021", "did:example:foo");
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(vm),
            ..Default::default()
        };
        let doc = ExampleDocument;
        let _proof = LinkedDataProofs::sign(&doc, &issue_options, &key)
            .await
            .unwrap();
    }
    */
}
