use std::collections::HashMap as Map;
#[cfg(feature = "keccak-hash")]
use std::convert::TryFrom;

use async_trait::async_trait;
use chrono::prelude::*;
pub mod proof;
pub use proof::{Check, LinkedDataProofOptions, Proof};
pub mod context;
pub mod error;
pub use error::Error;
pub mod soltx;
pub use context::Context;

// use crate::did::{VerificationMethod, VerificationMethodMap};
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedData;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_core::uri::URI;
use ssi_crypto::hashes::sha256::sha256;
use ssi_dids::did_resolve::{resolve_key, DIDResolver};
use ssi_dids::VerificationRelationship as ProofPurpose;
use ssi_json_ld::{rdf::DataSet, urdna2015, ContextLoader};
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use ssi_jws::Header;

pub mod suites;
pub use suites::*;

// TODO: factor out proof types
lazy_static::lazy_static! {
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
// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// Object summarizing a verification
/// Reference: vc-http-api
pub struct VerificationResult {
    /// The checks performed
    pub checks: Vec<Check>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Errors
    pub errors: Vec<String>,
}

impl VerificationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error(err: &str) -> Self {
        Self {
            checks: vec![],
            warnings: vec![],
            errors: vec![err.to_string()],
        }
    }

    pub fn append(&mut self, other: &mut Self) {
        self.checks.append(&mut other.checks);
        self.warnings.append(&mut other.warnings);
        self.errors.append(&mut other.errors);
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.errors.push(error);
        self
    }
}

impl From<Result<VerificationWarnings, Error>> for VerificationResult {
    fn from(res: Result<VerificationWarnings, Error>) -> Self {
        match res {
            Ok(warnings) => Self {
                checks: vec![],
                warnings,
                errors: vec![],
            },
            Err(error) => Self {
                checks: vec![],
                warnings: vec![],
                errors: vec![error.to_string()],
            },
        }
    }
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
            return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
            #[cfg(feature = "keccak-hash")]
            &Eip712Signature2021
        }
        "EthereumPersonalSignature2021" => {
            #[cfg(not(feature = "keccak-hash"))]
            return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
            #[cfg(feature = "keccak-hash")]
            &EthereumPersonalSignature2021
        }
        "EthereumEip712Signature2021" => {
            #[cfg(not(feature = "keccak-hash"))]
            return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
            #[cfg(feature = "keccak-hash")]
            &EthereumEip712Signature2021
        }
        "TezosSignature2021" => &TezosSignature2021,
        "TezosJcsSignature2021" => &TezosJcsSignature2021,
        "SolanaSignature2021" => &SolanaSignature2021,
        "AleoSignature2021" => {
            #[cfg(not(feature = "aleosig"))]
            return Err(Error::JWS(ssi_jws::Error::MissingFeatures("aleosig")));
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
        Algorithm::ES384 => &JsonWebSignature2020,
        Algorithm::AleoTestnet1Signature => {
            #[cfg(not(feature = "aleosig"))]
            return Err(Error::JWS(ssi_jws::Error::MissingFeatures("aleosig")));
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
                return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
                #[cfg(feature = "keccak-hash")]
                &EthereumEip712Signature2021
            } else if use_epsig(jwk) {
                #[cfg(not(feature = "keccak-hash"))]
                return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
                #[cfg(feature = "keccak-hash")]
                &EthereumPersonalSignature2021
            } else {
                match verification_method {
                    Some(URI::String(ref vm))
                        if (vm.starts_with("did:ethr:") || vm.starts_with("did:pkh:eth:"))
                            && vm.ends_with("#Eip712Method2021") =>
                    {
                        #[cfg(not(feature = "keccak-hash"))]
                        return Err(Error::JWS(ssi_jws::Error::MissingFeatures("keccak-hash")));
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
        context_loader: &mut ContextLoader,
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error>;

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error>;
}

pub use ssi_jws::VerificationWarnings;

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
pub async fn ensure_or_pick_verification_relationship(
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
        ensure_verification_relationship(issuer, proof_purpose, vm_id, key, resolver).await?;
    } else {
        options.verification_method = Some(URI::String(
            pick_default_vm(issuer, proof_purpose, key, resolver).await?,
        ))
    }
    Ok(())
}

// Ensure a verification relationship exists between a given issuer and verification method for a
// given proof purpose, and that the given JWK is matches the given verification method.
async fn ensure_verification_relationship(
    issuer: &str,
    proof_purpose: ProofPurpose,
    vm: &str,
    jwk: &JWK,
    resolver: &dyn DIDResolver,
) -> Result<(), Error> {
    let vmms =
        ssi_dids::did_resolve::get_verification_methods(issuer, proof_purpose.clone(), resolver)
            .await?;
    let vmm = vmms.get(vm).ok_or_else(|| {
        Error::MissingVerificationRelationship(issuer.to_string(), proof_purpose, vm.to_string())
    })?;
    vmm.match_jwk(jwk)?;
    Ok(())
}

async fn pick_default_vm(
    issuer: &str,
    proof_purpose: ProofPurpose,
    jwk: &JWK,
    resolver: &dyn DIDResolver,
) -> Result<String, Error> {
    let vm_ids =
        ssi_dids::did_resolve::get_verification_methods(issuer, proof_purpose.clone(), resolver)
            .await?;
    let mut err = Error::MissingKey;
    for (vm_id, vmm) in vm_ids {
        // Try to find a VM that matches this JWK and controller.
        match vmm.match_jwk(jwk) {
            Ok(()) => {
                // Found appropriate VM.
                return Ok(vm_id);
            }
            Err(e) => err = e.into(),
        }
    }
    // No matching VM found. Return any error encountered.
    Err(err)
}

pub struct LinkedDataProofs;
impl LinkedDataProofs {
    // https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
    pub async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
            .sign(
                document,
                &options,
                resolver,
                context_loader,
                key,
                extra_proof_properties,
            )
            .await
    }

    /// Prepare to create a linked data proof. Given a linked data document, proof options, and JWS
    /// algorithm, calculate the signing input bytes. Returns a [`ProofPreparation`] - the data for the caller to sign, along with data to reconstruct the proof.
    pub async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
                context_loader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        let suite = get_proof_suite(proof.type_.as_str())?;
        suite
            .verify(proof, document, resolver, context_loader)
            .await
    }
}

async fn to_jws_payload(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
    context_loader: &mut ContextLoader,
) -> Result<Vec<u8>, Error> {
    let sigopts_dataset = proof
        .to_dataset_for_signing(Some(document), context_loader)
        .await?;
    let doc_dataset = document
        .to_dataset_for_signing(None, context_loader)
        .await?;
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let sigopts_digest = sha256(sigopts_normalized.as_bytes());
    let doc_digest = sha256(doc_normalized.as_bytes());
    let data = [
        sigopts_digest.as_ref().to_vec(),
        doc_digest.as_ref().to_vec(),
    ]
    .concat();
    Ok(data)
}

#[allow(clippy::too_many_arguments)]
async fn sign(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    _resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<Proof, Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
        }
    }
    let proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    sign_proof(document, proof, key, algorithm, context_loader).await
}

async fn sign_proof(
    document: &(dyn LinkedDataDocument + Sync),
    mut proof: Proof,
    key: &JWK,
    algorithm: Algorithm,
    context_loader: &mut ContextLoader,
) -> Result<Proof, Error> {
    let message = to_jws_payload(document, &proof, context_loader).await?;
    let jws = ssi_jws::detached_sign_unencoded_payload(algorithm, &message, key)?;
    proof.jws = Some(jws);
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
async fn sign_nojws(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    context_loader: &mut ContextLoader,
    key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    context_uri: &str,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<Proof, Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
        }
    }
    let mut proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    if !document_has_context(document, context_uri)? {
        proof.context = serde_json::json!([context_uri]);
    }
    let message = to_jws_payload(document, &proof, context_loader).await?;
    let sig = ssi_jws::sign_bytes(algorithm, &message, key)?;
    let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);
    proof.proof_value = Some(sig_multibase);
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
async fn prepare(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    _resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    public_key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<ProofPreparation, Error> {
    if let Some(key_algorithm) = public_key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
        }
    }
    let proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    prepare_proof(document, proof, algorithm, context_loader).await
}

async fn prepare_proof(
    document: &(dyn LinkedDataDocument + Sync),
    proof: Proof,
    algorithm: Algorithm,
    context_loader: &mut ContextLoader,
) -> Result<ProofPreparation, Error> {
    let message = to_jws_payload(document, &proof, context_loader).await?;
    let (jws_header, signing_input) =
        ssi_jws::prepare_detached_unencoded_payload(algorithm, &message)?;
    Ok(ProofPreparation {
        proof,
        jws_header: Some(jws_header),
        signing_input: SigningInput::Bytes(Base64urlUInt(signing_input)),
    })
}

#[allow(clippy::too_many_arguments)]
async fn prepare_nojws(
    document: &(dyn LinkedDataDocument + Sync),
    options: &LinkedDataProofOptions,
    context_loader: &mut ContextLoader,
    public_key: &JWK,
    type_: &str,
    algorithm: Algorithm,
    context_uri: &str,
    extra_proof_properties: Option<Map<String, Value>>,
) -> Result<ProofPreparation, Error> {
    if let Some(key_algorithm) = public_key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
        }
    }
    let mut proof = Proof::new(type_)
        .with_options(options)
        .with_properties(extra_proof_properties);
    if !document_has_context(document, context_uri)? {
        proof.context = serde_json::json!([context_uri]);
    }
    let message = to_jws_payload(document, &proof, context_loader).await?;
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
    let jws = ssi_jws::complete_sign_unencoded_payload(jws_header, signature)?;
    proof.jws = Some(jws);
    Ok(proof)
}

async fn verify(
    proof: &Proof,
    document: &(dyn LinkedDataDocument + Sync),
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
) -> Result<VerificationWarnings, Error> {
    let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
    let verification_method = proof
        .verification_method
        .as_ref()
        .ok_or(Error::MissingVerificationMethod)?;
    let key = resolve_key(verification_method, resolver).await?;
    let message = to_jws_payload(document, proof, context_loader).await?;
    ssi_jws::detached_verify(jws, &message, &key)?;
    Ok(Default::default())
}

async fn verify_nojws(
    proof: &Proof,
    document: &(dyn LinkedDataDocument + Sync),
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
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
    let key = resolve_key(verification_method, resolver).await?;
    let message = to_jws_payload(document, proof, context_loader).await?;
    let (_base, sig) = multibase::decode(proof_value)?;
    Ok(ssi_jws::verify_bytes_warnable(
        algorithm, &message, &key, &sig,
    )?)
}

// Check if a linked data document has a given URI in its @context array.
fn document_has_context(
    document: &(dyn LinkedDataDocument + Sync),
    context_uri: &str,
) -> Result<bool, Error> {
    let contexts_string = document.get_contexts()?.ok_or(Error::MissingContext)?;
    let contexts: ssi_core::one_or_many::OneOrMany<Context> =
        serde_json::from_str(&contexts_string)?;
    Ok(contexts.into_iter().any(|c| match c {
        Context::URI(URI::String(u)) if u == context_uri => true,
        _ => false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::example::DIDExample;
    use ssi_json_ld::CREDENTIALS_V1_CONTEXT;

    struct ExampleDocument;

    #[async_trait]
    impl LinkedDataDocument for ExampleDocument {
        fn get_contexts(&self) -> Result<Option<String>, Error> {
            Ok(Some(serde_json::to_string(&*CREDENTIALS_V1_CONTEXT)?))
        }
        async fn to_dataset_for_signing(
            &self,
            _parent: Option<&(dyn LinkedDataDocument + Sync)>,
            _context_loader: &mut ContextLoader,
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let doc = ExampleDocument;
        let _proof = LinkedDataProofs::sign(
            &doc,
            &issue_options,
            &resolver,
            &mut context_loader,
            &key,
            None,
        )
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = LinkedDataProofs::sign(
            &doc,
            &issue_options,
            &resolver,
            &mut context_loader,
            &key,
            None,
        )
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = LinkedDataProofs::sign(
            &doc,
            &issue_options,
            &resolver,
            &mut context_loader,
            &key,
            None,
        )
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = LinkedDataProofs::sign(
            &doc,
            &issue_options,
            &resolver,
            &mut context_loader,
            &key,
            None,
        )
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
        const EXAMPLE_123_JSON: &str = include_str!("../../tests/esrs2020-did.jsonld");

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

        let vc_str = include_str!("../../tests/esrs2020-vc.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let mut n_proofs = 0;
        for proof in vc.proof.iter().flatten() {
            n_proofs += 1;
            let resolver = ExampleResolver;
            let mut context_loader = ssi_json_ld::ContextLoader::default();
            let warnings = EcdsaSecp256k1RecoverySignature2020
                .verify(proof, &vc, &resolver, &mut context_loader)
                .await
                .unwrap();
            assert!(warnings.is_empty());
        }
        assert_eq!(n_proofs, 4);
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
        let props = &vmm.property_set.unwrap();
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
            serde_json::from_str(include_str!("../../tests/lds-ed25519-2020-issuer0.jsonld"))
                .unwrap();

        let vc_str = include_str!("../../tests/lds-ed25519-2020-vc0.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let vp_str = include_str!("../../tests/lds-ed25519-2020-vp0.jsonld");
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

        let sk_jwk = JWK::from(JWKParams::OKP(jwk::OctetParams {
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();

        println!("{}", serde_json::to_string(&vc).unwrap());
        // reissue VC
        let new_proof = Ed25519Signature2020
            .sign(
                &vc,
                &issue_options,
                &resolver,
                &mut context_loader,
                &sk_jwk,
                None,
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VC proof and original proof
        Ed25519Signature2020
            .verify(&new_proof, &vc, &resolver, &mut context_loader)
            .await
            .unwrap();
        let orig_proof = vc.proof.iter().flatten().next().unwrap();
        Ed25519Signature2020
            .verify(orig_proof, &vc, &resolver, &mut context_loader)
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
            .sign(
                &vp,
                &vp_issue_options,
                &resolver,
                &mut context_loader,
                &sk_jwk,
                None,
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VP proof and original proof
        Ed25519Signature2020
            .verify(&new_proof, &vp, &resolver, &mut context_loader)
            .await
            .unwrap();
        let orig_proof = vp.proof.iter().flatten().next().unwrap();
        Ed25519Signature2020
            .verify(orig_proof, &vp, &resolver, &mut context_loader)
            .await
            .unwrap();

        // Try using prepare/complete
        let pk_jwk = sk_jwk.to_public();
        let prep = Ed25519Signature2020
            .prepare(
                &vp,
                &vp_issue_options,
                &resolver,
                &mut context_loader,
                &pk_jwk,
                None,
            )
            .await
            .unwrap();
        let signing_input_bytes = match prep.signing_input {
            SigningInput::Bytes(Base64urlUInt(ref bytes)) => bytes,
            _ => panic!("expected SigningInput::Bytes for Ed25519Signature2020 preparation"),
        };
        let sig = ssi_jws::sign_bytes(Algorithm::EdDSA, signing_input_bytes, &sk_jwk).unwrap();
        let sig_mb = multibase::encode(multibase::Base::Base58Btc, sig);
        let completed_proof = Ed25519Signature2020.complete(prep, &sig_mb).await.unwrap();
        Ed25519Signature2020
            .verify(&completed_proof, &vp, &resolver, &mut context_loader)
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
        const EXAMPLE_DOC: &'static str = include_str!("../../tests/lds-aleo2021-issuer0.jsonld");
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
            serde_json::from_str(include_str!("../../tests/aleotestnet1-2021-11-22.json")).unwrap();

        let vc_str = include_str!("../../tests/lds-aleo2021-vc0.jsonld");
        let mut vc = Credential::from_json_unsigned(vc_str).unwrap();
        let resolver = ExampleResolver;
        let mut context_loader = ssi_json_ld::ContextLoader::default();

        if vc.proof.iter().flatten().next().is_none() {
            // Issue VC / Generate Test Vector
            let mut credential = vc.clone();
            let vc_issue_options = LinkedDataProofOptions {
                verification_method: Some(URI::String("did:example:aleovm2021#id".to_string())),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            };
            let proof = AleoSignature2021
                .sign(
                    &vc,
                    &vc_issue_options,
                    &resolver,
                    &mut context_loader,
                    &private_key,
                    None,
                )
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
            .verify(&proof, &vc, &resolver, &mut context_loader)
            .await
            .unwrap();
        assert!(warnings.is_empty());
    }
}
