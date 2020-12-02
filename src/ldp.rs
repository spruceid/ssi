use std::convert::TryFrom;

use chrono::prelude::*;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, EncodingKey, Header};
use ring::digest;
use serde_json::value::Value;

use crate::error::Error;
use crate::jwk::{OctetParams as JWKOctetParams, Params as JWKParams, JWK};
use crate::rdf::DataSet;
use crate::vc::{base64_encode_json, LinkedDataProofOptions, Proof};

// Get current time to millisecond precision if possible
pub fn now_ms() -> DateTime<Utc> {
    let datetime = Utc::now();
    let ms = datetime.timestamp_subsec_millis();
    let ns = ms * 1_000_000;
    datetime.with_nanosecond(ns).unwrap_or(datetime)
}

pub trait LinkedDataDocument {
    fn to_dataset_for_signing(&self) -> Result<DataSet, Error>;
}

pub trait ProofSuite {
    fn sign(
        document: &dyn LinkedDataDocument,
        options: &LinkedDataProofOptions,
        key: &EncodingKey,
    ) -> Result<Proof, Error>;
    fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error>;
}

pub struct LinkedDataProofs {}
impl LinkedDataProofs {
    // https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
    pub fn sign(
        document: &dyn LinkedDataDocument,
        options: &LinkedDataProofOptions,
        jwk: &JWK,
    ) -> Result<Proof, Error> {
        let key = EncodingKey::try_from(jwk)?;
        match jwk {
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
            } => return RsaSignature2018::sign(document, options, &key),
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
                    return Ed25519Signature2018::sign(document, options, &key);
                }
                _ => {}
            },
            _ => {}
        };
        return Err(Error::ProofTypeNotImplemented);
    }

    // https://w3c-ccg.github.io/ld-proofs/#proof-verification-algorithm
    pub fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error> {
        match proof.type_.as_str() {
            "RsaSignature2018" => RsaSignature2018::verify(proof, document),
            "Ed25519Signature2018" => Ed25519Signature2018::verify(proof, document),
            "Ed25519VerificationKey2018" => Ed25519Signature2018::verify(proof, document), // invalid/deprecated
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

fn to_signing_input(
    document: &dyn LinkedDataDocument,
    header_b64: &str,
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let doc_normalized = document.to_dataset_for_signing()?.to_nquads()?;
    let sigopts_normalized = proof.to_dataset_for_signing()?.to_nquads()?;
    let sigopts_digest = digest::digest(&digest::SHA256, sigopts_normalized.as_bytes());
    let doc_digest = digest::digest(&digest::SHA256, doc_normalized.as_bytes());
    let data = [
        sigopts_digest.as_ref().to_vec(),
        doc_digest.as_ref().to_vec(),
    ]
    .concat();
    let message = [header_b64.as_bytes(), b".", data.as_slice()].concat();
    Ok(message)
}

fn sign(
    document: &dyn LinkedDataDocument,
    options: &LinkedDataProofOptions,
    key: &EncodingKey,
    type_: &str,
    algorithm: Algorithm,
) -> Result<Proof, Error> {
    let mut header = Header::default();
    header.alg = algorithm;
    let mut params = std::collections::HashMap::new();
    params.insert("b64".to_string(), false.into());
    header.params = Some(params);
    header.crit = Some(vec!["b64".to_string()]);
    // header.kid = Some(key_id.clone());
    let mut proof = Proof {
        type_: type_.to_string(),
        proof_purpose: options.proof_purpose.clone(),
        proof_value: None,
        verification_method: options.verification_method.clone(),
        creator: None,
        created: Some(options.created.unwrap_or(now_ms())),
        domain: options.domain.clone(),
        expires: None,
        challenge: options.challenge.clone(),
        nonce: None,
        property_set: None,
        jws: None,
    };
    let header_b64 = base64_encode_json(&header)?;
    let message = to_signing_input(document, &header_b64, &proof)?;
    let sig = jsonwebtoken::crypto::sign_bytes(&message, &key, header.alg)?;
    proof.jws = Some([&header_b64, "", &sig].join("."));
    Ok(proof)
}

fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error> {
    let jws = match &proof.jws {
        None => return Err(Error::MissingProofSignature),
        Some(jws) => jws,
    };

    let ref verification_method = match &proof.verification_method {
        Some(verification_method) => verification_method,
        None => return Err(Error::MissingVerificationMethod),
    };
    let jwk = resolve_key(verification_method)?;
    let key = DecodingKey::try_from(&jwk)?;

    let mut parts = jws.splitn(3, '.');
    let (header_b64, signature_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(header_b64), Some(""), Some(signature_b64)) => (header_b64, signature_b64),
        _ => return Err(Error::InvalidSignature),
    };
    let header = decode_header(jws)?;
    let b64: Option<bool> = match header.params {
        Some(params) => match params.get("b64") {
            Some(Value::Bool(boolean)) => Some(*boolean),
            Some(_) => None,
            None => None,
        },
        None => None,
    };
    if b64 != Some(false) {
        return Err(Error::ExpectedUnencodedHeader);
    }
    for name in header.crit.iter().flatten() {
        match name.as_str() {
            "b64" => {}
            _ => {
                return Err(Error::UnknownCriticalHeader);
            }
        }
    }

    let message = to_signing_input(document, &header_b64, proof)?;
    let verified = jsonwebtoken::crypto::verify_bytes(signature_b64, &message, &key, header.alg)?;
    if !verified {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

pub struct RsaSignature2018 {}
impl ProofSuite for RsaSignature2018 {
    fn sign(
        document: &dyn LinkedDataDocument,
        options: &LinkedDataProofOptions,
        key: &EncodingKey,
    ) -> Result<Proof, Error> {
        sign(document, options, key, "RsaSignature2018", Algorithm::RS256)
    }

    fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error> {
        verify(proof, document)
    }
}

pub struct Ed25519Signature2018 {}
impl ProofSuite for Ed25519Signature2018 {
    fn sign(
        document: &dyn LinkedDataDocument,
        options: &LinkedDataProofOptions,
        key: &EncodingKey,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            key,
            "Ed25519Signature2018",
            Algorithm::EdDSA,
        )
    }

    fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error> {
        verify(proof, document)
    }
}
