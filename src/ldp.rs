use async_trait::async_trait;
use chrono::prelude::*;

// use crate::did::{VerificationMethod, VerificationMethodMap};
use crate::did::{Resource, Source};
use crate::did_resolve::{dereference, Content, DIDResolver, DereferencingInputMetadata};
use crate::error::Error;
use crate::hash::sha256;
use crate::jwk::{Algorithm, OctetParams as JWKOctetParams, Params as JWKParams, JWK};
use crate::rdf::DataSet;
use crate::urdna2015;
use crate::vc::{LinkedDataProofOptions, Proof};

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

    async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        verify(proof, document, resolver).await
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
            _ => Err(Error::ProofTypeNotImplemented),
        }
    }
}

/// Resolve a verificationMethod to a key
pub async fn resolve_key(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<JWK, Error> {
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
        Content::Null => return Err(Error::ResourceNotFound),
        _ => return Err(Error::ExpectedObject),
    };
    vm.public_key_jwk.ok_or(Error::MissingKey)
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
        type_: type_.to_string(),
        proof_purpose: options.proof_purpose.clone(),
        proof_value: None,
        verification_method: options.verification_method.clone(),
        creator: None,
        created: Some(options.created.unwrap_or_else(now_ms)),
        domain: options.domain.clone(),
        challenge: options.challenge.clone(),
        nonce: None,
        property_set: None,
        jws: None,
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
        property_set.insert("publicKeyJwk".to_string(), jwk_value);
        let proof = Proof {
            type_: "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021".to_string(),
            proof_purpose: options.proof_purpose.clone(),
            proof_value: None,
            verification_method: options.verification_method.clone(),
            creator: None,
            created: Some(options.created.unwrap_or_else(now_ms)),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            nonce: None,
            jws: None,
            property_set: Some(property_set),
        };
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        sign_proof(document, proof, key, Algorithm::EdDSA).await
    }

    async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<(), Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let didtz = resolver.to_did_method().ok_or(Error::MissingKey)?;
        let jwk: JWK = match proof.property_set {
            Some(ref props) => {
                let jwk_value = props.get("publicKeyJwk").ok_or(Error::MissingKey)?;
                serde_json::from_value(jwk_value.clone())?
            }
            None => return Err(Error::MissingKey),
        };
        let did = didtz
            .generate(&Source::Key(&jwk))
            .ok_or(Error::MissingKey)?;
        if Some(did + "#blockchainAccountId") != proof.verification_method {
            return Err(Error::KeyMismatch);
        }
        let message = to_jws_payload(document, proof).await?;
        crate::jws::detached_verify(&jws, &message, &jwk)?;
        Ok(())
    }
}
