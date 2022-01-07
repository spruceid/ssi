use std::collections::HashMap as Map;
#[cfg(feature = "keccak-hash")]
use std::convert::TryFrom;

use async_trait::async_trait;
use chrono::prelude::*;

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
use crate::jwk::{Algorithm, Params as JWKParams, JWK};
use crate::jws::Header;
use crate::rdf::DataSet;
use crate::urdna2015;
use crate::vc::{LinkedDataProofOptions, Proof, ProofPurpose, URI};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// TODO: factor out proof types
lazy_static! {
    /// JSON-LD context for Linked Data Proofs based on Tezos addresses
    pub static ref TZ_CONTEXT: Value = {
        let context_str = ssi_contexts::TZ_V2;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref TZVM_CONTEXT: Value = {
        let context_str = ssi_contexts::TZVM_V1;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref TZJCSVM_CONTEXT: Value = {
        let context_str = ssi_contexts::TZJCSVM_V1;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref EIP712VM_CONTEXT: Value = {
        let context_str = ssi_contexts::EIP712VM;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref EPSIG_CONTEXT: Value = {
        let context_str = ssi_contexts::EPSIG_V0_1;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref SOLVM_CONTEXT: Value = {
        let context_str = ssi_contexts::SOLVM;
        serde_json::from_str(context_str).unwrap()
    };
    pub static ref ALEOVM_CONTEXT: Value = {
        let context_str = ssi_contexts::ALEOVM;
        serde_json::from_str(context_str).unwrap()
    };
}

pub fn get_proof_suite(proof_type: &str) -> Result<&(dyn ProofSuite + Sync), Error> {
    Ok(match proof_type {
        "RsaSignature2018" => &RsaSignature2018,
        "Ed25519Signature2018" => &Ed25519Signature2018,
        "Ed25519Signature2020" => &Ed25519Signature2020,
        "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
            &Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        }
        "P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
            &P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        }
        "EcdsaSecp256k1Signature2019" => &EcdsaSecp256k1Signature2019,
        "EcdsaSecp256k1RecoverySignature2020" => &EcdsaSecp256k1RecoverySignature2020,
        "Eip712Signature2021" => {
            #[cfg(not(feature = "keccak-hash"))]
            return Err(Error::MissingFeatures("keccak-hash"));
            #[cfg(feature = "keccak-hash")]
            &Eip712Signature2021
        }
        "EthereumPersonalSignature2021" => {
            #[cfg(not(feature = "keccak-hash"))]
            return Err(Error::MissingFeatures("keccak-hash"));
            #[cfg(feature = "keccak-hash")]
            &EthereumPersonalSignature2021
        }
        "EthereumEip712Signature2021" => {
            #[cfg(not(feature = "keccak-hash"))]
            return Err(Error::MissingFeatures("keccak-hash"));
            #[cfg(feature = "keccak-hash")]
            &EthereumEip712Signature2021
        }
        "TezosSignature2021" => &TezosSignature2021,
        "TezosJcsSignature2021" => &TezosJcsSignature2021,
        "SolanaSignature2021" => &SolanaSignature2021,
        "AleoSignature2021" => {
            #[cfg(not(feature = "aleosig"))]
            return Err(Error::MissingFeatures("aleosig"));
            #[cfg(feature = "aleosig")]
            &AleoSignature2021
        }
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
        Algorithm::PS256 => &JsonWebSignature2020,
        Algorithm::AleoTestnet1Signature => {
            #[cfg(not(feature = "aleosig"))]
            return Err(Error::MissingFeatures("aleosig"));
            #[cfg(feature = "aleosig")]
            &AleoSignature2021
        }
        Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
            Some(URI::String(ref vm))
                if (vm.starts_with("did:sol:") || vm.starts_with("did:pkh:sol:"))
                    && vm.ends_with("#SolanaMethod2021") =>
            {
                &SolanaSignature2021
            }
            Some(URI::String(ref vm))
                if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
            {
                if vm.ends_with("#TezosMethod2021") {
                    &TezosSignature2021
                } else {
                    &Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                }
            }
            _ => &Ed25519Signature2018,
        },
        Algorithm::ES256 | Algorithm::ESBlake2b => match verification_method {
            Some(URI::String(ref vm))
                if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
            {
                if vm.ends_with("#TezosMethod2021") {
                    &TezosSignature2021
                } else {
                    &P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                }
            }
            _ => &JsonWebSignature2020,
        },
        Algorithm::ES256K | Algorithm::ESBlake2bK => match verification_method {
            Some(URI::String(ref vm))
                if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
            {
                if vm.ends_with("#TezosMethod2021") {
                    &TezosSignature2021
                } else {
                    &EcdsaSecp256k1RecoverySignature2020
                }
            }
            _ => &EcdsaSecp256k1Signature2019,
        },
        Algorithm::ES256KR =>
        {
            #[allow(clippy::if_same_then_else)]
            if use_eip712sig(jwk) {
                #[cfg(not(feature = "keccak-hash"))]
                return Err(Error::MissingFeatures("keccak-hash"));
                #[cfg(feature = "keccak-hash")]
                &EthereumEip712Signature2021
            } else if use_epsig(jwk) {
                #[cfg(not(feature = "keccak-hash"))]
                return Err(Error::MissingFeatures("keccak-hash"));
                #[cfg(feature = "keccak-hash")]
                &EthereumPersonalSignature2021
            } else {
                match verification_method {
                    Some(URI::String(ref vm))
                        if (vm.starts_with("did:ethr:") || vm.starts_with("did:pkh:eth:"))
                            && vm.ends_with("#Eip712Method2021") =>
                    {
                        #[cfg(not(feature = "keccak-hash"))]
                        return Err(Error::MissingFeatures("keccak-hash"));
                        #[cfg(feature = "keccak-hash")]
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
    fn get_default_proof_purpose(&self) -> Option<ProofPurpose> {
        None
    }
    fn get_issuer(&self) -> Option<&str> {
        None
    }
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
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error>;

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error>;
}

pub use crate::jws::VerificationWarnings;

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
    // deprecated: allow using unregistered "signTypedData" key operation value to indicate using EthereumEip712Signature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signTypedData".to_string()) {
            return true;
        }
    }
    false
}

fn use_epsig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signPersonalMessage" key operation value to indicate using EthereumPersonalSignature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signPersonalMessage".to_string()) {
            return true;
        }
    }
    false
}

// If a verificationMethod purpose was not provided, pick one. If one was provided,
// verify that it is correct for the given issuer and proof purpose.
pub(crate) async fn ensure_or_pick_verification_relationship(
    options: &mut LinkedDataProofOptions,
    document: &(dyn LinkedDataDocument + Sync),
    key: &JWK,
    resolver: &dyn DIDResolver,
) -> Result<(), Error> {
    let issuer = match document.get_issuer() {
        None => {
            // No issuer: no check is done.
            // TODO: require issuer - or invokers set for ZCap
            return Ok(());
        }
        Some(issuer) => issuer,
    };
    if options.proof_purpose.is_none() {
        options.proof_purpose = document.get_default_proof_purpose();
    }
    let proof_purpose = options
        .proof_purpose
        .as_ref()
        .ok_or(Error::MissingProofPurpose)?
        .clone();
    if !issuer.starts_with("did:") {
        // TODO: support non-DID issuers.
        // Unable to verify verification relationship for non-DID issuers.
        // Allow some for testing purposes only.
        match issuer {
            #[cfg(feature = "example-http-issuer")]
            "https://example.edu/issuers/14" => {
                // https://github.com/w3c/vc-test-suite/blob/cdc7835/test/vc-data-model-1.0/input/example-016-jwt.jsonld#L8
                // We don't have a way to actually resolve this to anything. Just allow it for
                // vc-test-suite for now.
                return Ok(());
            }
            _ => {
                return Err(Error::UnsupportedNonDIDIssuer(issuer.to_string()));
            }
        }
    }
    if let Some(URI::String(ref vm_id)) = options.verification_method {
        crate::vc::ensure_verification_relationship(issuer, proof_purpose, vm_id, key, resolver)
            .await?;
    } else {
        options.verification_method = Some(URI::String(
            crate::vc::pick_default_vm(issuer, proof_purpose, key, resolver).await?,
        ))
    }
    Ok(())
}

pub struct LinkedDataProofs;
impl LinkedDataProofs {
    // https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
    pub async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
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
        let mut options = options.clone();
        ensure_or_pick_verification_relationship(&mut options, document, key, resolver).await?;
        suite
            .sign(document, &options, resolver, key, extra_proof_properties)
            .await
    }

    /// Prepare to create a linked data proof. Given a linked data document, proof options, and JWS
    /// algorithm, calculate the signing input bytes. Returns a [`ProofPreparation`] - the data for the caller to sign, along with data to reconstruct the proof.
    pub async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
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
        let mut options = options.clone();
        ensure_or_pick_verification_relationship(&mut options, document, public_key, resolver)
            .await?;
        suite
            .prepare(
                document,
                &options,
                resolver,
                public_key,
                extra_proof_properties,
            )
            .await
    }

    // https://w3c-ccg.github.io/ld-proofs/#proof-verification-algorithm
    pub async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<VerificationWarnings, Error> {
        let suite = get_proof_suite(proof.type_.as_str())?;
        suite.verify(proof, document, resolver).await
    }
}

/// Resolve a verificationMethod to a key
pub async fn resolve_key(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<JWK, Error> {
    let vmm = resolve_vm(verification_method, resolver).await?;
    let jwk = vmm.get_jwk()?;
    Ok(jwk)
}

/// Resolve a verificationMethod
pub async fn resolve_vm(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<VerificationMethodMap, Error> {
    let (res_meta, object, _meta) = dereference(
        resolver,
        verification_method,
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
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
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
    _resolver: &dyn DIDResolver,
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
    let jws = crate::jws::detached_sign_unencoded_payload(algorithm, &message, key)?;
    proof.jws = Some(jws);
    Ok(proof)
}

async fn sign_nojws(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    _resolver: &dyn DIDResolver,
    key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    context_uri: &str,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<Proof, Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let mut proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    if !document_has_context(document, context_uri)? {
        proof.context = serde_json::json!([context_uri]);
    }
    let message = to_jws_payload(document, &proof).await?;
    let sig = crate::jws::sign_bytes(algorithm, &message, &key)?;
    let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);
    proof.proof_value = Some(sig_multibase);
    Ok(proof)
}

async fn prepare(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    _resolver: &dyn DIDResolver,
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

async fn prepare_nojws(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    _resolver: &dyn DIDResolver,
    public_key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    context_uri: &str,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<ProofPreparation, Error> {
    if let Some(key_algorithm) = public_key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let mut proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    if !document_has_context(document, context_uri)? {
        proof.context = serde_json::json!([context_uri]);
    }
    let message = to_jws_payload(document, &proof).await?;
    Ok(ProofPreparation {
        proof,
        jws_header: None,
        signing_input: SigningInput::Bytes(Base64urlUInt(message)),
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
) -> Result<VerificationWarnings, Error> {
    let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
    let verification_method = proof
        .verification_method
        .as_ref()
        .ok_or(Error::MissingVerificationMethod)?;
    let key = resolve_key(verification_method, resolver).await?;
    let message = to_jws_payload(document, proof).await?;
    crate::jws::detached_verify(jws, &message, &key)?;
    Ok(Default::default())
}

async fn verify_nojws(
    proof: &Proof,
    document: &(dyn LinkedDataDocument + Sync),
    resolver: &dyn DIDResolver,
    algorithm: Algorithm,
) -> Result<VerificationWarnings, Error> {
    let proof_value = proof
        .proof_value
        .as_ref()
        .ok_or(Error::MissingProofSignature)?;
    let verification_method = proof
        .verification_method
        .as_ref()
        .ok_or(Error::MissingVerificationMethod)?;
    let key = resolve_key(&verification_method, resolver).await?;
    let message = to_jws_payload(document, proof).await?;
    let (_base, sig) = multibase::decode(proof_value)?;
    crate::jws::verify_bytes_warnable(algorithm, &message, &key, &sig)
}

pub struct RsaSignature2018;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for RsaSignature2018 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
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
        resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
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
    ) -> Result<VerificationWarnings, Error> {
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
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
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
        resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
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
    ) -> Result<VerificationWarnings, Error> {
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

pub struct Ed25519Signature2020;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for Ed25519Signature2020 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign_nojws(
            document,
            options,
            resolver,
            key,
            "Ed25519Signature2020",
            Algorithm::EdDSA,
            crate::jsonld::W3ID_ED2020_V1_CONTEXT,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<VerificationWarnings, Error> {
        verify_nojws(proof, document, resolver, Algorithm::EdDSA).await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare_nojws(
            document,
            options,
            resolver,
            public_key,
            "Ed25519Signature2020",
            Algorithm::EdDSA,
            crate::jsonld::W3ID_ED2020_V1_CONTEXT,
            extra_proof_properties,
        )
        .await
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
}

pub struct EcdsaSecp256k1Signature2019;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for EcdsaSecp256k1Signature2019 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
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
        resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
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
    ) -> Result<VerificationWarnings, Error> {
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
        _resolver: &dyn DIDResolver,
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
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "EcdsaSecp256k1RecoveryMethod2020"
            && vm.type_ != "EcdsaSecp256k1VerificationKey2019"
            && vm.type_ != "JsonWebKey2020"
        {
            return Err(Error::VerificationMethodMismatch);
        }
        let message = to_jws_payload(document, proof).await?;
        let (_header, jwk) = crate::jws::detached_recover(jws, &message)?;
        let mut warnings = VerificationWarnings::default();
        if let Err(_e) = vm.match_jwk(&jwk) {
            // Legacy mode: allow using Keccak-256 instead of SHA-256
            let (_header, jwk) = crate::jws::detached_recover_legacy_keccak_es256kr(jws, &message)?;
            vm.match_jwk(&jwk)?;
            warnings.push(
                "Signature uses legacy mode EcdsaSecp256k1RecoveryMethod2020 with Keccak-256"
                    .to_string(),
            );
        }
        Ok(warnings)
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
        _resolver: &dyn DIDResolver,
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
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
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
        let vm = resolve_vm(verification_method, resolver).await?;
        vm.match_jwk(&jwk)?;
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(jws, &message, &jwk)?;
        Ok(Default::default())
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
        _resolver: &dyn DIDResolver,
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
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
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
        let vm = resolve_vm(verification_method, resolver).await?;
        vm.match_jwk(&jwk)?;
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(jws, &message, &jwk)?;
        Ok(Default::default())
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
        _resolver: &dyn DIDResolver,
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
        sig_bytes[64] += 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        match &vm.type_[..] {
            "Eip712Method2021" => (),
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => return Err(Error::VerificationMethodMismatch),
        };
        let typed_data = TypedData::from_document_and_options(document, proof).await?;
        let bytes = typed_data.bytes()?;
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
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
        _resolver: &dyn DIDResolver,
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
            context: serde_json::json!(crate::jsonld::EIP712SIG_V1_CONTEXT),
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
        sig_bytes[64] += 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            context: serde_json::json!(crate::jsonld::EIP712SIG_V1_CONTEXT),
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
    ) -> Result<VerificationWarnings, Error> {
        use std::str::FromStr;
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        match &vm.type_[..] {
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => return Err(Error::VerificationMethodMismatch),
        };
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)?;
        let typed_data = TypedData::from_document_and_options_json(document, proof).await?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
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
        _resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        use k256::ecdsa::signature::Signer;
        let mut proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new("EthereumPersonalSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let signing_string = string_from_document_and_options(document, &proof).await?;
        let hash = crate::keccak_hash::prefix_personal_message(&signing_string);
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(Error::KeyTypeNotImplemented),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature = signing_key.try_sign(&hash)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] += 27;
        let sig_hex = crate::keccak_hash::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        match &vm.type_[..] {
            "EcdsaSecp256k1VerificationKey2019" => (),
            "EcdsaSecp256k1RecoveryMethod2020" => (),
            _ => return Err(Error::VerificationMethodMismatch),
        };
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64])?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)?;
        let signing_string = string_from_document_and_options(document, proof).await?;
        let hash = crate::keccak_hash::prefix_personal_message(&signing_string);
        let recovered_key = sig.recover_verify_key(&hash)?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
    }
}

async fn micheline_from_document_and_options(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let msg = ["", &sigopts_normalized, &doc_normalized].join("\n");
    let data = crate::tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

async fn micheline_from_document_and_options_jcs(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let mut doc_value = document.to_value()?;
    let doc_obj = doc_value.as_object_mut().ok_or(Error::ExpectedObject)?;
    let mut proof_value = serde_json::to_value(proof)?;
    let proof_obj = proof_value.as_object_mut().ok_or(Error::ExpectedObject)?;
    proof_obj.remove("proofValue");
    doc_obj.insert("proof".to_string(), proof_value);
    let msg = serde_jcs::to_string(&doc_value)?;
    let data = crate::tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

#[cfg(feature = "keccak-hash")]
async fn string_from_document_and_options(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<String, Error> {
    let sigopts_dataset = proof.to_dataset_for_signing(Some(document)).await?;
    let doc_dataset = document.to_dataset_for_signing(None).await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
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
        _resolver: &dyn DIDResolver,
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
        sig_prefixed.extend_from_slice(prefix);
        sig_prefixed.extend_from_slice(&sig);
        let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
        proof.proof_value = Some(sig_bs58);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
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
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "TezosMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }

        let micheline = micheline_from_document_and_options(document, proof).await?;
        let account_id_opt: Option<BlockchainAccountId> = match vm.blockchain_account_id {
            Some(account_id_string) => Some(account_id_string.parse()?),
            None => None,
        };

        // VM must have either publicKeyJwk or blockchainAccountId.
        let warnings = if let Some(vm_jwk) = vm.public_key_jwk {
            // If VM has publicKey, use that to verify the signature.
            crate::jws::verify_bytes_warnable(algorithm, &micheline, &vm_jwk, &sig)?
            // Note: VM blockchainAccountId is ignored in this case.
        } else if let Some(account_id) = account_id_opt {
            // VM does not have publicKeyJwk: proof must have public key
            if let Some(proof_jwk) = proof_jwk_opt {
                // Proof has public key: verify it with blockchainAccountId,
                account_id.verify(&proof_jwk)?;
                // and verify the signature.
                crate::jws::verify_bytes_warnable(algorithm, &micheline, &proof_jwk, &sig)?
            } else {
                return Err(Error::MissingKey);
            }
        } else {
            return Err(Error::MissingKey);
        };
        Ok(warnings)
    }
}

pub struct TezosJcsSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for TezosJcsSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        let tzpk = crate::tzkey::jwk_to_tezos_key(&key.to_public())?;
        let pkmb = "z".to_string() + &tzpk;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyMultibase".to_string(), Value::String(pkmb));
        let mut proof = Proof {
            context: TZJCSVM_CONTEXT.clone(),
            ..Proof::new("TezosJcsSignature2021")
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
        sig_prefixed.extend_from_slice(prefix);
        sig_prefixed.extend_from_slice(&sig);
        let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
        proof.proof_value = Some(sig_bs58);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        // TODO: dereference VM URL to check if VM already contains public key.
        // "z" is multibase for base58. Usually publicKeyMultibase is used with multicodec, but
        // here we use it for Tezos-style base58 key representation.
        let pkmb = "z".to_string() + &crate::tzkey::jwk_to_tezos_key(&public_key.to_public())?;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyMultibase".to_string(), Value::String(pkmb));

        let proof = Proof {
            context: TZJCSVM_CONTEXT.clone(),
            ..Proof::new("TezosJcsSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        let micheline = micheline_from_document_and_options_jcs(document, &proof).await?;
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
    ) -> Result<VerificationWarnings, Error> {
        let sig_bs58 = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let mut proof_jwk_opt: Option<JWK> = None;
        let mut proof_pkmb_opt: Option<&str> = None;
        if let Some(ref props) = proof.property_set {
            if let Some(jwk_value) = props.get("publicKeyJwk") {
                proof_jwk_opt = Some(serde_json::from_value(jwk_value.clone())?);
            }
            if let Some(pkmb_value) = props.get("publicKeyMultibase") {
                if proof_jwk_opt.is_some() {
                    return Err(Error::MultipleKeyMaterial);
                }
                proof_pkmb_opt = pkmb_value.as_str();
            }
        }

        let (algorithm, sig) = crate::tzkey::decode_tzsig(sig_bs58)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "TezosMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }

        let micheline = micheline_from_document_and_options_jcs(document, proof).await?;
        let account_id_opt: Option<BlockchainAccountId> = match vm.blockchain_account_id {
            Some(account_id_string) => Some(account_id_string.parse()?),
            None => None,
        };

        // VM must have either publicKeyJwk or blockchainAccountId.
        let mut warnings = if let Some(vm_jwk) = vm.public_key_jwk {
            // If VM has publicKey, use that to verify the signature.
            crate::jws::verify_bytes_warnable(algorithm, &micheline, &vm_jwk, &sig)?
            // Note: VM blockchainAccountId is ignored in this case.
        } else if let Some(account_id) = account_id_opt {
            // VM does not have publicKeyJwk: proof must have public key
            if let Some(proof_pkmb) = proof_pkmb_opt {
                if !proof_pkmb.starts_with('z') {
                    return Err(Error::ExpectedMultibaseZ);
                }
                proof_jwk_opt = Some(crate::tzkey::jwk_from_tezos_key(&proof_pkmb[1..])?);
            }
            if let Some(proof_jwk) = proof_jwk_opt {
                // Proof has public key: verify it with blockchainAccountId,
                account_id.verify(&proof_jwk)?;
                // and verify the signature.
                crate::jws::verify_bytes_warnable(algorithm, &micheline, &proof_jwk, &sig)?
            } else {
                return Err(Error::MissingKey);
            }
        } else {
            return Err(Error::MissingKey);
        };
        warnings.push("TezosJcsSignature2021 is experimental.".to_string());
        Ok(warnings)
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
        _resolver: &dyn DIDResolver,
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
        _resolver: &dyn DIDResolver,
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
    ) -> Result<VerificationWarnings, Error> {
        let sig_b58 = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "SolanaMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }
        let key = vm.public_key_jwk.ok_or(Error::MissingKey)?;
        let message = to_jws_payload(document, proof).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let sig = bs58::decode(&sig_b58).into_vec()?;
        crate::jws::verify_bytes_warnable(Algorithm::EdDSA, &bytes, &key, &sig)
    }
}

#[cfg(feature = "aleosig")]
/// Aleo Signature 2021
///
/// Linked data signature suite using [Aleo](crate::aleo).
///
/// # Suite definition
///
/// Aleo Signature 2021 is a [Linked Data Proofs][ld-proofs] signature suite consisting of the
/// following algorithms:
///
/// |         Parameter          |               Value               |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |id                          |https://w3id.org/security#AleoSignature2021|[this document](#)  |
/// |[canonicalization algorithm]|https://w3id.org/security#URDNA2015|[RDF Dataset Normalization 1.0][URDNA2015]|
/// |[message digest algorithm]  |[SHA-256]                          |[RFC4634]                   |
/// |[signature algorithm]       |Schnorr signature with [Edwards BLS12] curve|[Aleo Documentation - Accounts][aleo-accounts]|
///
/// The proof object must contain a [proofValue] property encoding the signature in
/// [Multibase] format.
///
/// ## Verification method
///
/// Aleo Signature 2021 may be used with the following verification method types:
///
/// |            Name            |                IRI                |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |       AleoMethod2021       |https://w3id.org/security#AleoMethod2021|   [this document](#)  |
/// |BlockchainVerificationMethod2021|https://w3id.org/security#BlockchainVerificationMethod2021|[Blockchain Vocabulary v1][blockchainvm2021]
///
/// The verification method object must have a [blockchainAccountId] property, identifying the
/// signer's Aleo
/// account address and network id for verification purposes. The chain id part of the account address
/// identifies an Aleo network as specified in the proposed [CAIP for Aleo Blockchain
/// Reference][caip-aleo-chain-ref]. Signatures use parameters defined per network. Currently only
/// network id "1" (CAIP-2 "aleo:1" / [Aleo Testnet I][testnet1]) is supported. The account
/// address format is documented in [Aleo
/// documentation](https://developer.aleo.org/aleo/concepts/accounts#account-address).
///
/// [message digest algorithm]: https://w3id.org/security#digestAlgorithm
/// [signature algorithm]: https://w3id.org/security#signatureAlgorithm
/// [canonicalization algorithm]: https://w3id.org/security#canonicalizationAlgorithm
/// [ld-proofs]: https://w3c-ccg.github.io/ld-proofs/
/// [proofValue]: https://w3id.org/security#proofValue
/// [Multibase]: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
/// [URDNA2015]: https://json-ld.github.io/rdf-dataset-canonicalization/spec/
/// [RFC4634]: https://www.rfc-editor.org/rfc/rfc4634 "US Secure Hash Algorithms (SHA and HMAC-SHA)"
/// [SHA-256]: http://www.w3.org/2001/04/xmlenc#sha256
/// [Edwards BLS12]: https://developer.aleo.org/autogen/advanced/the_aleo_curves/edwards_bls12
/// [aleo-accounts]: https://developer.aleo.org/aleo/concepts/accounts
/// [blockchainvm2021]: https://w3id.org/security/suites/blockchain-2021#BlockchainVerificationMethod2021
/// [blockchainAccountId]: https://w3c-ccg.github.io/security-vocab/#blockchainAccountId
/// [caip-aleo-chain-ref]: https://github.com/ChainAgnostic/CAIPs/pull/84
/// [testnet1]: https://developer.aleo.org/testnet/getting_started/overview/
pub struct AleoSignature2021;
#[cfg(feature = "aleosig")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for AleoSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let has_context = document_has_context(document, "TODO:uploadAleoVMContextSomewhere")?;
        let mut proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ALEOVM_CONTEXT.clone()])
            },
            ..Proof::new("AleoSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        let sig = crate::aleo::sign(&message, &key)?;
        let sig_mb = multibase::encode(multibase::Base::Base58Btc, sig);
        proof.proof_value = Some(sig_mb);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("AleoSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
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
    ) -> Result<VerificationWarnings, Error> {
        const NETWORK_ID: &str = "1";
        const NAMESPACE: &str = "aleo";
        let sig_mb = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let (_base, sig) = multibase::decode(&sig_mb)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "AleoMethod2021" && vm.type_ != "BlockchainVerificationMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }
        let account_id: BlockchainAccountId =
            vm.blockchain_account_id.ok_or(Error::MissingKey)?.parse()?;
        if account_id.chain_id.namespace != NAMESPACE {
            return Err(Error::UnexpectedCAIP2Namepace(
                NAMESPACE.to_string(),
                account_id.chain_id.namespace.to_string(),
            ));
        }
        if account_id.chain_id.reference != NETWORK_ID {
            return Err(Error::UnexpectedAleoNetwork(
                NETWORK_ID.to_string(),
                account_id.chain_id.namespace.to_string(),
            ));
        }
        let message = to_jws_payload(document, proof).await?;
        crate::aleo::verify(&message, &account_id.account_address, &sig)?;
        Ok(Default::default())
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
        resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
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
        resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
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
    ) -> Result<VerificationWarnings, Error> {
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

// Check if a linked data document has a given URI in its @context array.
fn document_has_context(
    document: &(dyn LinkedDataDocument + Sync),
    context_uri: &str,
) -> Result<bool, Error> {
    let contexts_string = document.get_contexts()?.ok_or(Error::MissingContext)?;
    let contexts: crate::vc::Contexts = serde_json::from_str(&contexts_string)?;
    Ok(contexts.contains_uri(context_uri))
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
        _resolver: &dyn DIDResolver,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        self.validate_key_and_algorithm(key, algorithm)?;
        let has_context = document_has_context(document, crate::jsonld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([crate::jsonld::W3ID_JWS2020_V1_CONTEXT])
            },
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
        _resolver: &dyn DIDResolver,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let algorithm = public_key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        self.validate_key_and_algorithm(public_key, algorithm)?;
        let has_context = document_has_context(document, crate::jsonld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([crate::jsonld::W3ID_JWS2020_V1_CONTEXT])
            },
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
    ) -> Result<VerificationWarnings, Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let (header_b64, signature_b64) = crate::jws::split_detached_jws(jws)?;
        let message = to_jws_payload(document, proof).await?;
        let crate::jws::DecodedJWS {
            header,
            signing_input,
            payload: _,
            signature,
        } = crate::jws::decode_jws_parts(header_b64, &message, signature_b64)?;
        // Redundant early algorithm check before expensive key lookup and signature verification.
        self.validate_algorithm(header.algorithm)?;
        let key = resolve_key(verification_method, resolver).await?;
        self.validate_key_and_algorithm(&key, header.algorithm)?;
        crate::jws::verify_bytes_warnable(header.algorithm, &signing_input, &key, &signature)
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

impl JsonWebSignature2020 {
    fn validate_algorithm(&self, algorithm: Algorithm) -> Result<(), Error> {
        match algorithm {
            Algorithm::EdDSA => (),
            Algorithm::ES256K => (),
            Algorithm::ES256 => (),
            // Algorithm::ES384 => (), TODO
            Algorithm::PS256 => (),
            _ => return Err(Error::UnsupportedAlgorithm),
        }
        Ok(())
    }
    // https://w3c-ccg.github.io/lds-jws2020/#jose-conformance
    fn validate_key_and_algorithm(&self, key: &JWK, algorithm: Algorithm) -> Result<(), Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != algorithm {
                return Err(Error::AlgorithmMismatch);
            }
        }
        match &key.params {
            JWKParams::RSA(rsa_params) => {
                let public_modulus = &rsa_params.modulus.as_ref().ok_or(Error::MissingModulus)?.0;
                // Ensure 2048-bit key. Note it may have an extra byte:
                // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
                match public_modulus.len() {
                    256 | 257 => (),
                    _ => {
                        return Err(Error::InvalidKeyLength);
                    }
                }
                match algorithm {
                    Algorithm::PS256 => (),
                    _ => return Err(Error::UnsupportedAlgorithm),
                }
            }
            JWKParams::EC(ec_params) => {
                match &ec_params.curve.as_ref().ok_or(Error::MissingCurve)?[..] {
                    "secp256k1" => match algorithm {
                        Algorithm::ES256K => (),
                        _ => return Err(Error::UnsupportedAlgorithm),
                    },
                    "P-256" => match algorithm {
                        Algorithm::ES256 => (),
                        // Algorithm::ES384 => (), TODO
                        _ => return Err(Error::UnsupportedAlgorithm),
                    },
                    _ => {
                        return Err(Error::UnsupportedCurve);
                    }
                }
            }
            JWKParams::OKP(okp_params) => match &okp_params.curve[..] {
                "Ed25519" => match algorithm {
                    Algorithm::EdDSA => (),
                    _ => return Err(Error::UnsupportedAlgorithm),
                },
                _ => {
                    return Err(Error::UnsupportedCurve);
                }
            },
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::example::DIDExample;
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
        let resolver = DIDExample;
        let doc = ExampleDocument;
        let _proof = LinkedDataProofs::sign(&doc, &issue_options, &resolver, &key, None)
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
        let resolver = DIDExample;
        let proof = LinkedDataProofs::sign(&doc, &issue_options, &resolver, &key, None)
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
        let resolver = DIDExample;
        let proof = LinkedDataProofs::sign(&doc, &issue_options, &resolver, &key, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&proof).unwrap());
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn tezos_jcs_vm_tz2() {
        let mut key = JWK::generate_secp256k1().unwrap();
        key.algorithm = Some(Algorithm::ESBlake2bK);
        let vm = format!("{}#TezosMethod2021", "did:example:foo");
        let issue_options = LinkedDataProofOptions {
            type_: Some(String::from("TezosJcsSignature2021")),
            verification_method: Some(URI::String(vm)),
            ..Default::default()
        };
        let doc = ExampleDocument;
        let resolver = DIDExample;
        let proof = LinkedDataProofs::sign(&doc, &issue_options, &resolver, &key, None)
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
        let resolver = DIDExample;
        let _proof = LinkedDataProofs::sign(&doc, &issue_options, &resolver, &key)
            .await
            .unwrap();
    }
    */

    #[async_std::test]
    #[cfg(all(feature = "secp256k1", feature = "keccak-hash"))]
    async fn esrs2020() {
        use crate::did::Document;
        use crate::did_resolve::{
            DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
            TYPE_DID_LD_JSON,
        };
        use crate::vc::Credential;

        struct ExampleResolver;

        const EXAMPLE_123_ID: &str = "did:example:123";
        const EXAMPLE_123_JSON: &'static str = include_str!("../tests/esrs2020-did.jsonld");

        #[async_trait]
        impl DIDResolver for ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                if did == EXAMPLE_123_ID {
                    let doc = match Document::from_json(EXAMPLE_123_JSON) {
                        Ok(doc) => doc,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!("JSON Error: {:?}", err)),
                                None,
                                None,
                            );
                        }
                    };
                    (
                        ResolutionMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
                }
            }

            async fn resolve_representation(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
                if did == EXAMPLE_123_ID {
                    let vec = EXAMPLE_123_JSON.as_bytes().to_vec();
                    (
                        ResolutionMetadata {
                            error: None,
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            property_set: None,
                        },
                        vec,
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (
                        ResolutionMetadata::from_error(ERROR_NOT_FOUND),
                        Vec::new(),
                        None,
                    )
                }
            }
        }

        let vc_str = include_str!("../tests/esrs2020-vc.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let mut n_proofs = 0;
        for proof in vc.proof.iter().flatten() {
            n_proofs += 1;
            let resolver = ExampleResolver;
            let warnings = EcdsaSecp256k1RecoverySignature2020
                .verify(&proof, &vc, &resolver)
                .await
                .unwrap();
            assert!(warnings.is_empty());
        }
        assert_eq!(n_proofs, 3);
    }

    #[async_std::test]
    async fn ed2020() {
        use crate::vc::{Credential, Presentation};

        // https://w3c-ccg.github.io/lds-ed25519-2020/#example-4
        let vmm: VerificationMethodMap = serde_json::from_value(serde_json::json!({
          "id": "https://example.com/issuer/123#key-0",
          "type": "Ed25519KeyPair2020",
          "controller": "https://example.com/issuer/123",
          "publicKeyMultibase": "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
          "privateKeyMultibase": "zrv3kJcnBP1RpYmvNZ9jcYpKBZg41iSobWxSg3ix2U7Cp59kjwQFCT4SZTgLSL3HP8iGMdJs3nedjqYgNn6ZJmsmjRm"
        }))
        .unwrap();

        let sk_hex = "9b937b81322d816cfab9d5a3baacc9b2a5febe4b149f126b3630f93a29527017095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk_bytes_mc = [vec![0x80, 0x26], sk_bytes.clone()].concat();
        let sk_mb = multibase::encode(multibase::Base::Base58Btc, &sk_bytes_mc);
        let ref props = vmm.property_set.unwrap();
        let sk_mb_expected = props
            .get("privateKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(&sk_mb, &sk_mb_expected);

        let pk_hex = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let pk_bytes_mc = [vec![0xed, 0x01], pk_bytes.clone()].concat();
        let pk_mb = multibase::encode(multibase::Base::Base58Btc, &pk_bytes_mc);
        let pk_mb_expected = props
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(&pk_mb, &pk_mb_expected);

        assert_eq!(&sk_bytes[32..64], &pk_bytes);

        let issuer_document: Document =
            serde_json::from_str(include_str!("../tests/lds-ed25519-2020-issuer0.jsonld")).unwrap();

        let vc_str = include_str!("../tests/lds-ed25519-2020-vc0.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let vp_str = include_str!("../tests/lds-ed25519-2020-vp0.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();

        // "DID Resolver" for HTTPS issuer used in the test vectors.
        struct ED2020ExampleResolver {
            issuer_document: Document,
        }
        use crate::did::{Document, PrimaryDIDURL};
        use crate::did_resolve::{
            ContentMetadata, DereferencingMetadata, DocumentMetadata, ResolutionInputMetadata,
            ResolutionMetadata, ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
        };
        #[async_trait]
        impl DIDResolver for ED2020ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                // Return empty result here to allow DID URL dereferencing to proceed. The DID
                // is resolved as part of DID URL dereferencing, but the DID document is not used.
                if did == "https:" {
                    let doc_meta = DocumentMetadata::default();
                    let doc = Document::new(did);
                    return (ResolutionMetadata::default(), Some(doc), Some(doc_meta));
                }
                (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
            }

            async fn dereference(
                &self,
                did_url: &PrimaryDIDURL,
                _input_metadata: &DereferencingInputMetadata,
            ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
                match &did_url.to_string()[..] {
                    "https://example.com/issuer/123" => Some((
                        DereferencingMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Content::DIDDocument(self.issuer_document.clone()),
                        ContentMetadata::default(),
                    )),
                    _ => None,
                }
            }
        }

        let sk_jwk = JWK::from(JWKParams::OKP(crate::jwk::OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(sk_bytes[32..64].to_vec()),
            private_key: Some(Base64urlUInt(sk_bytes[0..32].to_vec())),
        }));
        assert_eq!(sk_bytes.len(), 64);
        eprintln!("{}", serde_json::to_string(&sk_jwk).unwrap());

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(
                "https://example.com/issuer/123#key-0".to_string(),
            )),
            proof_purpose: Some(ProofPurpose::AssertionMethod),
            created: Some(Utc::now().with_nanosecond(0).unwrap()),
            ..Default::default()
        };

        let resolver = ED2020ExampleResolver { issuer_document };

        println!("{}", serde_json::to_string(&vc).unwrap());
        // reissue VC
        let new_proof = Ed25519Signature2020
            .sign(&vc, &issue_options, &resolver, &sk_jwk, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VC proof and original proof
        Ed25519Signature2020
            .verify(&new_proof, &vc, &resolver)
            .await
            .unwrap();
        let orig_proof = vc.proof.iter().flatten().next().unwrap();
        Ed25519Signature2020
            .verify(orig_proof, &vc, &resolver)
            .await
            .unwrap();

        // re-generate VP proof
        let vp_issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(
                "https://example.com/issuer/123#key-0".to_string(),
            )),
            proof_purpose: Some(ProofPurpose::Authentication),
            created: Some(Utc::now().with_nanosecond(0).unwrap()),
            challenge: Some("123".to_string()),
            ..Default::default()
        };
        let new_proof = Ed25519Signature2020
            .sign(&vp, &vp_issue_options, &resolver, &sk_jwk, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VP proof and original proof
        Ed25519Signature2020
            .verify(&new_proof, &vp, &resolver)
            .await
            .unwrap();
        let orig_proof = vp.proof.iter().flatten().next().unwrap();
        Ed25519Signature2020
            .verify(orig_proof, &vp, &resolver)
            .await
            .unwrap();

        // Try using prepare/complete
        let pk_jwk = sk_jwk.to_public();
        let prep = Ed25519Signature2020
            .prepare(&vp, &vp_issue_options, &resolver, &pk_jwk, None)
            .await
            .unwrap();
        let signing_input_bytes = match prep.signing_input {
            SigningInput::Bytes(Base64urlUInt(ref bytes)) => bytes,
            _ => panic!("expected SigningInput::Bytes for Ed25519Signature2020 preparation"),
        };
        let sig = crate::jws::sign_bytes(Algorithm::EdDSA, &signing_input_bytes, &sk_jwk).unwrap();
        let sig_mb = multibase::encode(multibase::Base::Base58Btc, sig);
        let completed_proof = Ed25519Signature2020.complete(prep, &sig_mb).await.unwrap();
        Ed25519Signature2020
            .verify(&completed_proof, &vp, &resolver)
            .await
            .unwrap();
    }

    #[async_std::test]
    #[cfg(feature = "aleosig")]
    async fn aleosig2021() {
        use crate::did::Document;
        use crate::did_resolve::{
            DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
            TYPE_DID_LD_JSON,
        };
        use crate::vc::Credential;

        struct ExampleResolver;
        const EXAMPLE_DID: &str = "did:example:aleovm2021";
        const EXAMPLE_DOC: &'static str = include_str!("../tests/lds-aleo2021-issuer0.jsonld");
        #[async_trait]
        impl DIDResolver for ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                if did == EXAMPLE_DID {
                    let doc = match Document::from_json(EXAMPLE_DOC) {
                        Ok(doc) => doc,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!("JSON Error: {:?}", err)),
                                None,
                                None,
                            );
                        }
                    };
                    (
                        ResolutionMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
                }
            }
        }

        let private_key: JWK =
            serde_json::from_str(include_str!("../tests/aleotestnet1-2021-11-22.json")).unwrap();

        let vc_str = include_str!("../tests/lds-aleo2021-vc0.jsonld");
        let mut vc = Credential::from_json_unsigned(vc_str).unwrap();
        let resolver = ExampleResolver;

        if vc.proof.iter().flatten().next().is_none() {
            // Issue VC / Generate Test Vector
            let mut credential = vc.clone();
            let vc_issue_options = LinkedDataProofOptions {
                verification_method: Some(URI::String("did:example:aleovm2021#id".to_string())),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            };
            let proof = AleoSignature2021
                .sign(&vc, &vc_issue_options, &resolver, &private_key, None)
                .await
                .unwrap();
            credential.add_proof(proof.clone());
            vc = credential;

            use std::fs::File;
            use std::io::{BufWriter, Write};
            let outfile = File::create("tests/lds-aleo2021-vc0.jsonld").unwrap();
            let mut output_writer = BufWriter::new(outfile);
            serde_json::to_writer_pretty(&mut output_writer, &vc).unwrap();
            output_writer.write(b"\n").unwrap();
        }

        // Verify VC
        let proof = vc.proof.iter().flatten().next().unwrap();
        let warnings = AleoSignature2021
            .verify(&proof, &vc, &resolver)
            .await
            .unwrap();
        assert!(warnings.is_empty());
    }
}
