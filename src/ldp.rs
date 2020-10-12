use std::convert::TryFrom;

use chrono::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use ring::digest;

use crate::error::Error;
use crate::jwk::{Header, JWK};
use crate::rdf::DataSet;
use crate::vc::{base64_encode_json, LinkedDataProofOptions, Proof};

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
        key: &EncodingKey,
    ) -> Result<Proof, Error> {
        RsaSignature2018::sign(document, options, key)
    }

    // https://w3c-ccg.github.io/ld-proofs/#proof-verification-algorithm
    pub fn verify(proof: &Proof, document: &dyn LinkedDataDocument) -> Result<(), Error> {
        match proof.type_.as_str() {
            "RsaSignature2018" => RsaSignature2018::verify(proof, document),
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

pub struct RsaSignature2018 {}
impl ProofSuite for RsaSignature2018 {
    fn sign(
        document: &dyn LinkedDataDocument,
        options: &LinkedDataProofOptions,
        key: &EncodingKey,
    ) -> Result<Proof, Error> {
        let mut header = Header::default();
        header.algorithm = Algorithm::RS256;
        header.base64urlencode_payload = Some(false);
        header.critical = Some(vec!["b64".to_string()]);
        // header.key_id = Some(key_id.clone());
        let mut proof = Proof {
            type_: "RsaSignature2018".to_string(),
            proof_purpose: options.proof_purpose.clone(),
            proof_value: None,
            verification_method: options.verification_method.clone(),
            creator: None,
            created: Some(options.created.unwrap_or(Utc::now())),
            domain: options.domain.clone(),
            expires: None,
            challenge: options.challenge.clone(),
            nonce: None,
            property_set: None,
            jws: None,
        };
        let header_b64 = base64_encode_json(&header)?;
        let message = to_signing_input(document, &header_b64, &proof)?;
        // https://github.com/Keats/jsonwebtoken/pull/150
        let message_str = unsafe { String::from_utf8_unchecked(message) };
        let sig = jsonwebtoken::crypto::sign(&message_str, &key, header.algorithm)?;
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
        let header = Header::from_b64(header_b64)?;
        if header.base64urlencode_payload != Some(false) {
            return Err(Error::ExpectedUnencodedHeader);
        }

        let message = to_signing_input(document, &header_b64, proof)?;
        // https://github.com/Keats/jsonwebtoken/pull/150
        let message_str = unsafe { String::from_utf8_unchecked(message) };
        let verified =
            jsonwebtoken::crypto::verify(signature_b64, &message_str, &key, header.algorithm)?;
        if !verified {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}
