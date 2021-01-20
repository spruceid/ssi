use async_trait::async_trait;
use chrono::prelude::*;

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
    ) -> Result<(), Error> {
        verify(proof, document).await
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
    ) -> Result<(), Error> {
        match proof.type_.as_str() {
            "RsaSignature2018" => RsaSignature2018::verify(proof, document).await,
            "Ed25519Signature2018" => Ed25519Signature2018::verify(proof, document).await,
            "Ed25519VerificationKey2018" => Ed25519Signature2018::verify(proof, document).await, // invalid/deprecated
            _ => Err(Error::ProofTypeNotImplemented),
        }
    }
}

/// Resolve a verificationMethod to a key, synchronously
fn resolve_key(verification_method: &str) -> Result<JWK, Error> {
    #[cfg(test)]
    if &verification_method[..16] == "did:example:jwk:" {
        let jwk: JWK = serde_json::from_str(&verification_method[16..])?;
        return Ok(jwk);
    }
    if &verification_method[..8] == "did:key:" {
        return JWK::from_did_key(verification_method);
    }
    Err(Error::ResourceNotFound)
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
    let mut proof = Proof {
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
    let message = to_jws_payload(document, &proof).await?;
    let jws = crate::jws::detached_sign_unencoded_payload(algorithm, &message, &key)?;
    proof.jws = Some(jws);
    Ok(proof)
}

async fn verify(proof: &Proof, document: &(dyn LinkedDataDocument + Sync)) -> Result<(), Error> {
    let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
    let verification_method = proof
        .verification_method
        .as_ref()
        .ok_or(Error::MissingVerificationMethod)?;
    let key = resolve_key(&verification_method)?;
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
