use async_trait::async_trait;
use chrono::prelude::*;

// use crate::did::{VerificationMethod, VerificationMethodMap};
use crate::blakesig;
use crate::caip10::BlockchainAccountId;
use crate::did::{Resource, VerificationMethodMap};
use crate::did_resolve::{dereference, Content, DIDResolver, DereferencingInputMetadata};
use crate::error::Error;
use crate::hash::sha256;
use crate::jwk::{Algorithm, OctetParams as JWKOctetParams, Params as JWKParams, JWK};
use crate::jws::Header;
use crate::rdf::DataSet;
use crate::urdna2015;
use crate::vc::{LinkedDataProofOptions, Proof};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// TODO: factor out proof types
lazy_static! {
    /// JSON-LD context for Linked Data Proofs based on Tezos addresses
    pub static ref TZ_CONTEXT: Value = {
        let context_str = include_str!("../contexts/tz-2021-v1.jsonld");
        serde_json::from_str(&context_str).unwrap()
    };
    pub static ref ESRS2020_CONTEXT_EXTRA: Value = {
        let context_str = include_str!("../contexts/esrs2020-extra.jsonld");
        serde_json::from_str(&context_str).unwrap()
    };
}

// Get current time to millisecond precision if possible
pub fn now_ms() -> DateTime<Utc> {
    let datetime = Utc::now();
    let ms = datetime.timestamp_subsec_millis();
    let ns = ms * 1_000_000;
    datetime.with_nanosecond(ns).unwrap_or(datetime)
}

#[async_trait]
pub trait LinkedDataDocument {
    fn get_contexts(&self) -> Result<Option<String>, Error>;
    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error>;
}

#[async_trait]
pub trait ProofSuite {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error>;

    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error>;

    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error>;

    async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofPreparation {
    pub proof: Proof,
    pub jws_header: Header,
    pub signing_input: Vec<u8>,
}

impl ProofPreparation {
    pub async fn complete(self, signature: &str) -> Result<Proof, Error> {
        match self.proof.type_.as_str() {
            "RsaSignature2018" => RsaSignature2018::complete(self, signature).await,
            "Ed25519Signature2018" => Ed25519Signature2018::complete(self, signature).await,
            "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
                Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::complete(self, signature)
                    .await
            }
            "EcdsaSecp256k1Signature2019" => {
                EcdsaSecp256k1Signature2019::complete(self, signature).await
            }
            "EcdsaSecp256k1RecoverySignature2020" => {
                EcdsaSecp256k1RecoverySignature2020::complete(self, signature).await
            }
            _ => Err(Error::ProofTypeNotImplemented),
        }
    }
}

pub struct LinkedDataProofs;
impl LinkedDataProofs {
    // https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
    pub async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        match key {
            JWK {
                params: JWKParams::RSA(_),
                public_key_use: _,
                key_operations: _,
                algorithm: _,
                key_id: _,
                x509_url: _,
                x509_certificate_chain: _,
                x509_thumbprint_sha1: _,
                x509_thumbprint_sha256: _,
            } => return RsaSignature2018::sign(document, options, &key).await,
            JWK {
                params:
                    JWKParams::OKP(JWKOctetParams {
                        curve,
                        public_key: _,
                        private_key: _,
                    }),
                public_key_use: _,
                key_operations: _,
                algorithm: _,
                key_id: _,
                x509_url: _,
                x509_certificate_chain: _,
                x509_thumbprint_sha1: _,
                x509_thumbprint_sha256: _,
            } => match &curve[..] {
                "Ed25519" => {
                    if let Some(ref vm) = options.verification_method {
                        if vm.starts_with("did:tz:tz1") {
                            return Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::sign(document, options, &key).await;
                        }
                    }
                    return Ed25519Signature2018::sign(document, options, &key).await;
                }
                _ => {
                    return Err(Error::ProofTypeNotImplemented);
                }
            },
            JWK {
                params: JWKParams::EC(ec_params),
                public_key_use: _,
                key_operations: _,
                algorithm,
                key_id: _,
                x509_url: _,
                x509_certificate_chain: _,
                x509_thumbprint_sha1: _,
                x509_thumbprint_sha256: _,
            } if ec_params.curve == Some("secp256k1".to_string()) => {
                if algorithm.as_ref() == Some(&Algorithm::ES256KR) {
                    return EcdsaSecp256k1RecoverySignature2020::sign(document, options, &key)
                        .await;
                } else {
                    return EcdsaSecp256k1Signature2019::sign(document, options, &key).await;
                }
            }
            _ => {}
        };
        Err(Error::ProofTypeNotImplemented)
    }

    /// Prepare to create a linked data proof. Given a linked data document, proof options, and JWS
    /// algorithm, calculate the signing input bytes. Returns a [`ProofPreparation`] - the data for the caller to sign, along with data to reconstruct the proof.
    pub async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        match public_key.get_algorithm().ok_or(Error::MissingAlgorithm)? {
            Algorithm::RS256 => {
                return RsaSignature2018::prepare(document, options, public_key).await
            }
            Algorithm::EdDSA => {
                if let Some(ref vm) = options.verification_method {
                    if vm.starts_with("did:tz:tz1") {
                        return Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::prepare(
                            document, options, public_key,
                        )
                        .await;
                    }
                }
                return Ed25519Signature2018::prepare(document, options, public_key).await;
            }
            Algorithm::ES256K => {
                return EcdsaSecp256k1Signature2019::prepare(document, options, public_key).await
            }
            Algorithm::ES256KR => {
                return EcdsaSecp256k1RecoverySignature2020::prepare(document, options, public_key)
                    .await;
            }
            _ => {}
        };
        Err(Error::ProofTypeNotImplemented)
    }

    // https://w3c-ccg.github.io/ld-proofs/#proof-verification-algorithm
    pub async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        match proof.type_.as_str() {
            "RsaSignature2018" => RsaSignature2018::verify(proof, document, resolver).await,
            "Ed25519Signature2018" => Ed25519Signature2018::verify(proof, document, resolver).await,
            "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021" => {
                Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::verify(
                    proof, document, resolver,
                )
                .await
            }
            "EcdsaSecp256k1Signature2019" => {
                EcdsaSecp256k1Signature2019::verify(proof, document, resolver).await
            }
            "EcdsaSecp256k1RecoverySignature2020" => {
                EcdsaSecp256k1RecoverySignature2020::verify(proof, document, resolver).await
            }
            _ => Err(Error::ProofTypeNotImplemented),
        }
    }
}

/// Resolve a verificationMethod to a key
pub async fn resolve_key(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<JWK, Error> {
    let vm = resolve_vm(verification_method, resolver).await?;
    let key = vm.public_key_jwk.ok_or(Error::MissingKey)?;
    Ok(key)
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
) -> Result<Proof, Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let proof = Proof {
        proof_purpose: options.proof_purpose.clone(),
        verification_method: options.verification_method.clone(),
        created: Some(options.created.unwrap_or_else(now_ms)),
        domain: options.domain.clone(),
        challenge: options.challenge.clone(),
        ..Proof::new(type_)
    };
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
) -> Result<ProofPreparation, Error> {
    if let Some(key_algorithm) = public_key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    let proof = Proof {
        proof_purpose: options.proof_purpose.clone(),
        verification_method: options.verification_method.clone(),
        created: Some(options.created.unwrap_or_else(now_ms)),
        domain: options.domain.clone(),
        challenge: options.challenge.clone(),
        ..Proof::new(type_)
    };
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
        jws_header,
        signing_input,
    })
}

async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
    complete_proof(preparation, signature).await
}

async fn complete_proof(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
    let mut proof = preparation.proof;
    let jws = crate::jws::complete_sign_unencoded_payload(preparation.jws_header, signature)?;
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
#[async_trait]
impl ProofSuite for RsaSignature2018 {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        sign(document, options, key, "RsaSignature2018", Algorithm::RS256).await
    }
    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "RsaSignature2018",
            Algorithm::RS256,
        )
        .await
    }
    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct Ed25519Signature2018;
#[async_trait]
impl ProofSuite for Ed25519Signature2018 {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "Ed25519Signature2018",
            Algorithm::EdDSA,
        )
        .await
    }
    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "Ed25519Signature2018",
            Algorithm::EdDSA,
        )
        .await
    }
    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct EcdsaSecp256k1Signature2019;
#[async_trait]
impl ProofSuite for EcdsaSecp256k1Signature2019 {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "EcdsaSecp256k1Signature2019",
            Algorithm::ES256K,
        )
        .await
    }
    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            public_key,
            "EcdsaSecp256k1Signature2019",
            Algorithm::ES256K,
        )
        .await
    }
    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
}

pub struct EcdsaSecp256k1RecoverySignature2020;
#[async_trait]
impl ProofSuite for EcdsaSecp256k1RecoverySignature2020 {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::ES256KR {
                return Err(Error::AlgorithmMismatch);
            }
        }
        let proof = Proof {
            context: serde_json::json!([
                crate::jsonld::DIF_ESRS2020_CONTEXT,
                ESRS2020_CONTEXT_EXTRA.clone(),
            ]),
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options.verification_method.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
        };
        sign_proof(document, proof, key, Algorithm::ES256KR).await
    }

    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([
                crate::jsonld::DIF_ESRS2020_CONTEXT,
                ESRS2020_CONTEXT_EXTRA.clone(),
            ]),
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options.verification_method.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
        };
        prepare_proof(document, proof, Algorithm::ES256KR).await
    }

    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
        complete(preparation, signature).await
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
        let vm = resolve_vm(&verification_method, resolver).await?;
        if vm.type_ != "EcdsaSecp256k1RecoveryMethod2020" {
            return Err(Error::VerificationMethodMismatch);
        }
        let message = to_jws_payload(document, proof).await?;
        let (_header, jwk) = crate::jws::detached_recover(&jws, &message)?;
        let account_id_str = vm.blockchain_account_id.ok_or(Error::MissingAccountId)?;
        use std::str::FromStr;
        let account_id = BlockchainAccountId::from_str(&account_id_str)?;
        account_id.verify(&jwk)?;
        Ok(())
    }
}

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
#[async_trait]
impl ProofSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
    ) -> Result<Proof, Error> {
        use std::collections::HashMap;
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::EdDSA {
                return Err(Error::AlgorithmMismatch);
            }
        }
        let mut property_set = HashMap::new();
        let jwk_value = serde_json::to_value(key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        property_set.insert("publicKeyJwk".to_string(), jwk_value);
        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options.verification_method.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            property_set: Some(property_set),
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
        };
        sign_proof(document, proof, key, Algorithm::EdDSA).await
    }

    async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
    ) -> Result<ProofPreparation, Error> {
        use std::collections::HashMap;
        let mut property_set = HashMap::new();
        let jwk_value = serde_json::to_value(public_key.to_public())?;
        // This proof type must contain the public key, because the DID is based on the hash of the
        // public key, and the public key is not otherwise recoverable.
        property_set.insert("publicKeyJwk".to_string(), jwk_value);
        // It needs custom JSON_LD context too.
        let proof = Proof {
            context: TZ_CONTEXT.clone(),
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options.verification_method.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
        };
        prepare_proof(document, proof, Algorithm::EdDSA).await
    }

    async fn complete(preparation: ProofPreparation, signature: &str) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }

    async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        _resolver: &dyn DIDResolver,
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
        // The hash should be in the vM URL.
        let vm = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let hash = blakesig::hash_public_key(&jwk)?;
        let vm_base = vm.split('#').next().unwrap();
        if vm_base.split(':').find(|&h| h == &hash).is_none() {
            return Err(Error::KeyMismatch);
        }
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(&jws, &message, &jwk)?;
        Ok(())
    }
}
