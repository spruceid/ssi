#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// TODO reinstate Error::MissingFeatures ?

pub mod error;
use bbs::prelude::*;
pub use error::Error;
use serde::{Deserialize, Serialize};
use ssi_crypto::hashes::sha256::sha256;
use ssi_jwk::{Algorithm, Base64urlUInt, Params as JWKParams, JWK};
use std::collections::BTreeMap;
use std::convert::TryFrom;

pub type VerificationWarnings = Vec<String>;

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jku")]
    pub jwk_set_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JWK>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "typ")]
    pub type_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crit")]
    pub critical: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "b64")]
    pub base64urlencode_payload: Option<bool>,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(flatten)]
    pub additional_parameters: BTreeMap<String, serde_json::Value>,
}

fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

pub fn create_bbs_sig_input(payload: &JWSPayload) -> Vec<SignatureMessage> {
    let mut messages: Vec<SignatureMessage> = Vec::new();
    messages.push(SignatureMessage::hash(payload.header.as_bytes()));
    messages.push(SignatureMessage::hash(payload.sigopts_digest.as_ref()));

    for i in 0..payload.messages.len() {
        let message = payload.messages[i].as_bytes();
        messages.push(SignatureMessage::hash(message));
    }

    let mut num_messages = payload.messages.len() + 2;
    while num_messages < 100 {
        // todo 100 is hardcoded; use config
        messages.push(SignatureMessage::hash(b""));
        num_messages += 1;
    }
    messages
}

pub fn sign_bytes_v2(
    algorithm: Algorithm,
    key: &JWK,
    payload: &JWSPayload,
) -> Result<Vec<u8>, Error> {
    if let JWKParams::OKP(okp) = &key.params {
        if let Algorithm::BLS12381G2 = algorithm {
            let messages = create_bbs_sig_input(payload);

            let Base64urlUInt(pk_bytes) = &okp.public_key;
            let Base64urlUInt(sk_bytes) = okp.private_key.as_ref().unwrap();
            let pk = bbs::prelude::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
            let sk = bbs::prelude::SecretKey::try_from(sk_bytes.as_slice()).unwrap();

            let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();
            return Ok(signature.to_bytes_compressed_form().to_vec());
        }
    }

    let messages_str = payload.messages.join("");
    let messages_hash = sha256(messages_str.as_bytes());
    let data = [
        payload.header.as_bytes(),
        b".",
        payload.sigopts_digest.as_slice(),
        messages_hash.as_slice(),
    ]
    .concat();
    sign_bytes(algorithm, data.as_slice(), key)
}

pub fn generate_proof_nonce() -> String {
    let proof_nonce = Verifier::generate_proof_nonce();
    let proof_nonce_bytes = proof_nonce.to_bytes_compressed_form();
    let proof_nonce_str = base64::encode(proof_nonce_bytes.as_ref());
    proof_nonce_str
}

pub fn sign_bytes(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<Vec<u8>, Error> {
    let signature = match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let key_pair = ring::signature::RsaKeyPair::try_from(rsa_params)?;
            let padding_alg: &dyn ring::signature::RsaEncoding = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            let mut sig = vec![0u8; key_pair.public_modulus_len()];
            let rng = ring::rand::SystemRandom::new();
            key_pair.sign(padding_alg, &rng, data, &mut sig)?;
            sig
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let private_key = rsa::RsaPrivateKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    let rng = rand::rngs::OsRng {};
                    padding =
                        rsa::PaddingScheme::new_pss_with_salt::<sha2::Sha256, _>(rng, hash.size());
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            private_key
                .sign(padding, &hashed)
                .map_err(ssi_jwk::Error::from)?
        }
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if algorithm != Algorithm::EdDSA && algorithm != Algorithm::EdBlake2b {
                return Err(Error::UnsupportedAlgorithm);
            }
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => blake2::Blake2b::<U32>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                let key_pair = ring::signature::Ed25519KeyPair::try_from(okp)?;
                key_pair.sign(&hash).as_ref().to_vec()
            }
            // TODO: SymmetricParams
            #[cfg(all(feature = "ed25519", not(feature = "ring")))]
            {
                let secret = ed25519_dalek::SigningKey::try_from(okp)?;
                use ed25519_dalek::Signer;
                secret.sign(&hash).to_bytes().to_vec()
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "p384")]
            Algorithm::ES384 => {
                use p384::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = p384::SecretKey::try_from(ec)?;
                let signing_key = p384::ecdsa::SigningKey::from(secret_key);
                let sig: p384::ecdsa::Signature =
                    signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "p256")]
            Algorithm::ES256 => {
                use p256::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = p256::SecretKey::try_from(ec)?;
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let sig: p256::ecdsa::Signature =
                    signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256K => {
                use k256::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let sig: Signature = signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256KR => {
                use k256::ecdsa::{
                    signature::{digest::Digest, Signer},
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let (sig, rec_id) =
                    signing_key.sign_digest_recoverable(sha2::Sha256::new_with_prefix(data))?;
                let mut res = sig.to_bytes().to_vec();
                res.push(rec_id.to_byte());
                res
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESKeccakKR => {
                use k256::ecdsa::{
                    signature::{digest::Digest, Signer},
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let (sig, rec_id) = signing_key
                    .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(data))
                    .map_err(ssi_jwk::Error::from)?;
                let mut res = sig.to_bytes().to_vec();
                res.push(rec_id.to_byte());
                res
            }
            #[cfg(feature = "p256")]
            Algorithm::ESBlake2b => {
                use p256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = p256::SecretKey::try_from(ec)?;
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let sig: p256::ecdsa::Signature =
                    signing_key.try_sign_digest(blake2::Blake2b::<U32>::new_with_prefix(data))?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESBlake2bK => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let sig: k256::ecdsa::Signature =
                    signing_key.try_sign_digest(blake2::Blake2b::<U32>::new_with_prefix(data))?;
                sig.to_bytes().to_vec()
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm);
            }
        },
        _ => return Err(Error::JWK(ssi_jwk::Error::KeyTypeNotImplemented)),
    };
    clear_on_drop::clear_stack(1);
    Ok(signature)
}

pub fn sign_bytes_b64(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<String, Error> {
    let signature = sign_bytes(algorithm, data, key)?;
    let sig_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
    Ok(sig_b64)
}

pub fn sign_bytes_b64_v2(
    algorithm: Algorithm,
    key: &JWK,
    payload: &JWSPayload,
) -> Result<String, Error> {
    let signature = sign_bytes_v2(algorithm, key, payload)?;
    let sig_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
    Ok(sig_b64)
}

pub fn verify_payload(
    algorithm: Algorithm,
    key: &JWK,
    payload: &JWSPayload,
    signature: &[u8],
    disclosed_message_indices: Option<&Vec<usize>>,
    nonce: Option<&String>,
) -> Result<VerificationWarnings, Error> {
    let warnings = VerificationWarnings::default();

    match algorithm {
        Algorithm::BLS12381G2 => (),
        _ => {
            return Err(Error::UnsupportedAlgorithm);
        }
    }

    match &key.params {
        JWKParams::OKP(okp) => {
            match nonce {
                Some(n) => {
                    let proof = SignatureProof::try_from(signature).unwrap();

                    let Base64urlUInt(pk_bytes) = &okp.public_key;
                    let issuer_pk = PublicKey::try_from(pk_bytes.as_slice()).unwrap();
                    let proof_request = Verifier::new_proof_request(
                        disclosed_message_indices.unwrap().as_slice(),
                        &issuer_pk,
                    )
                    .unwrap();
                    let proof_nonce_bytes = base64::decode(n).unwrap();
                    assert!(proof_nonce_bytes.len() == 32);
                    let mut proof_nonce_bytes_sized: [u8; 32] = [0; 32];
                    proof_nonce_bytes_sized.clone_from_slice(proof_nonce_bytes.as_slice());
                    let proof_nonce = ProofNonce::from(proof_nonce_bytes_sized);

                    let result =
                        Verifier::verify_signature_pok(&proof_request, &proof, &proof_nonce);
                    match result {
                        Ok(message_hashes) => {
                            //eprintln!("Signature pok check passes");
                            let mut i = 0;
                            let mut credential_subject_id = "";
                            while i < payload.messages.len() {
                                let m = payload.messages[i].as_str();
                                if m.contains(
                                    "<https://www.w3.org/2018/credentials#credentialSubject>",
                                ) {
                                    let m_parts: Vec<&str> = m.split(' ').collect();
                                    credential_subject_id = m_parts[2];
                                    break;
                                }
                                i += 1;
                            }
                            assert!(
                                !credential_subject_id.is_empty(),
                                "credentialSubject node not found"
                            );

                            let mut first_claim_found = false;

                            i = 0;
                            while i < payload.messages.len() {
                                let m = payload.messages[i].as_str();
                                if m.starts_with(credential_subject_id) {
                                    first_claim_found = true;
                                    break;
                                }
                                i += 1;
                            }
                            assert!(first_claim_found, "No claims in derived credential");

                            /*for nq in payload.messages.iter() {
                                eprintln!("Message: {}", nq);
                            }*/

                            for revealed_hash in message_hashes {
                                //eprintln!("Checking hash for: {}", payload.messages[i].as_str());
                                let target_hash =
                                    SignatureMessage::hash(payload.messages[i].as_bytes());
                                if revealed_hash != target_hash {
                                    eprintln!("Hashes do not match");
                                    return Err(Error::InvalidSignature);
                                }

                                i += 1;
                            }
                        }
                        Err(_) => {
                            eprintln!("Signature pok check did not pass");
                            return Err(Error::InvalidSignature);
                        }
                    }
                }
                None => {
                    if signature.len() != 112 {
                        return Err(Error::InvalidSignature);
                    } else {
                        if disclosed_message_indices.is_some() {
                            return Err(Error::NonceNotProvided);
                        }

                        let mut signature_sized: [u8; 112] = [0; 112];
                        signature_sized.clone_from_slice(signature);
                        let bbs_sig = bbs::prelude::Signature::from(&signature_sized);

                        let messages = create_bbs_sig_input(payload);
                        let Base64urlUInt(pk_bytes) = &okp.public_key;
                        let pk = bbs::prelude::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
                        let result = bbs_sig.verify(messages.as_slice(), &pk).unwrap();

                        if !result {
                            return Err(Error::InvalidSignature);
                        }
                    }
                }
            }
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm);
        }
    }

    Ok(warnings)
}

pub fn verify_bytes_warnable(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<VerificationWarnings, Error> {
    #[allow(unused_mut)]
    let mut warnings = VerificationWarnings::default();
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm
            && !(key_algorithm == Algorithm::EdDSA && algorithm == Algorithm::EdBlake2b)
            && !(key_algorithm == Algorithm::ES256 && algorithm == Algorithm::ESBlake2b)
            && !(key_algorithm == Algorithm::ES256K && algorithm == Algorithm::ESBlake2bK)
            && !(key_algorithm == Algorithm::ES256KR && algorithm == Algorithm::ESBlake2bK)
        {
            return Err(Error::AlgorithmMismatch);
        }
    }
    match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use ring::signature::RsaPublicKeyComponents;
            let public_key = RsaPublicKeyComponents::try_from(rsa_params)?;
            let parameters = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            public_key.verify(parameters, data, signature)?
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use rsa::PublicKey;
            let public_key =
                rsa::RsaPublicKey::try_from(rsa_params).map_err(ssi_jwk::Error::from)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let rng = rand::rngs::OsRng {};
                    padding = rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rng);
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            public_key
                .verify(padding, &hashed, signature)
                .map_err(ssi_jwk::Error::from)?;
        }
        // TODO: SymmetricParams
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => <blake2::Blake2b<U32> as Digest>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                use ring::signature::UnparsedPublicKey;
                let verification_algorithm = &ring::signature::ED25519;
                let public_key = UnparsedPublicKey::new(verification_algorithm, &okp.public_key.0);
                public_key.verify(&hash, signature)?;
            }
            #[cfg(feature = "ed25519")]
            {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let signature: ed25519_dalek::Signature =
                    signature.try_into().map_err(ssi_jwk::Error::from)?;
                public_key
                    .verify(&hash, &signature)
                    .map_err(ssi_jwk::Error::from)?;
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::ES256 => {
                use p256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256K => {
                use k256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                let normalized_sig = if let Some(s) = sig.normalize_s() {
                    // For user convenience, output the normalized signature.
                    let sig_normalized_b64 =
                        base64::encode_config(s.to_bytes(), base64::URL_SAFE_NO_PAD);
                    warnings.push(format!(
                        "Non-normalized ES256K signature. Normalized: {sig_normalized_b64}"
                    ));
                    s
                } else {
                    sig
                };
                verifying_key
                    .verify(data, &normalized_sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256KR => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier, Verifier,
                    },
                    RecoveryId, VerifyingKey,
                };
                if signature.len() != 65 {
                    Err(k256::ecdsa::Error::new())?;
                }
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(ssi_jwk::Error::from)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(ssi_jwk::Error::from)?;
                match VerifyingKey::recover_from_digest(
                    <sha2::Sha256 as Digest>::new_with_prefix(data),
                    &sig,
                    rec_id,
                ) {
                    Err(_e) => {
                        // Legacy mode: allow using Keccak-256 instead of SHA-256
                        verify_bytes(Algorithm::ESKeccakKR, data, key, signature)?;
                        warnings.push(
                            "Signature uses legacy mode ES256K-R with Keccak-256".to_string(),
                        );
                    }
                    Ok(recovered_key) => match recovered_key == verifying_key {
                        true => (),
                        false => Err(k256::ecdsa::Error::new())?,
                    },
                }
            }
            #[cfg(feature = "eip")]
            Algorithm::ESKeccakKR => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier, Verifier,
                    },
                    RecoveryId, VerifyingKey,
                };
                if signature.len() != 65 {
                    Err(k256::ecdsa::Error::new())?;
                }
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(ssi_jwk::Error::from)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(ssi_jwk::Error::from)?;
                let recovered_key = VerifyingKey::recover_from_digest(
                    sha3::Keccak256::new_with_prefix(data),
                    &sig,
                    rec_id,
                )
                .map_err(ssi_jwk::Error::from)?;
                match recovered_key == verifying_key {
                    true => (),
                    false => Err(k256::ecdsa::Error::new())?,
                }
            }
            #[cfg(feature = "p256")]
            Algorithm::ESBlake2b => {
                use p256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESBlake2bK => {
                use k256::ecdsa::signature::{
                    digest::{consts::U32, Digest},
                    DigestVerifier,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp384r1")]
            Algorithm::ES384 => {
                use p384::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p384::PublicKey::try_from(ec)?;
                let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p384::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm);
            }
        },
        _ => return Err(Error::JWK(ssi_jwk::Error::KeyTypeNotImplemented)),
    }
    Ok(warnings)
}

pub fn verify_bytes(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<(), Error> {
    verify_bytes_warnable(algorithm, data, key, signature)?;
    Ok(())
}

/// Recover a key from a signature and message, if the algorithm supports this.  (e.g.
/// [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r))
pub fn recover(algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<JWK, Error> {
    match algorithm {
        #[cfg(feature = "secp256k1")]
        Algorithm::ES256KR => {
            use k256::ecdsa::VerifyingKey;
            if signature.len() != 65 {
                Err(k256::ecdsa::Error::new())?;
            }
            let sig =
                k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
            let rec_id =
                k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
            let hash = ssi_crypto::hashes::sha256::sha256(data);
            let digest = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::from_slice(&hash);
            let recovered_key = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
                .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK {
                params: JWKParams::EC(ECParams::try_from(
                    &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
                        .map_err(ssi_jwk::Error::from)?,
                )?),
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
        #[cfg(feature = "secp256k1")]
        Algorithm::ESKeccakKR => {
            use k256::ecdsa::{signature::digest::Digest, VerifyingKey};
            if signature.len() != 65 {
                Err(k256::ecdsa::Error::new())?;
            }
            let sig =
                k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
            let rec_id =
                k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
            let recovered_key = VerifyingKey::recover_from_digest(
                sha3::Keccak256::new_with_prefix(data),
                &sig,
                rec_id,
            )
            .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK::from(JWKParams::EC(ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
                    .map_err(ssi_jwk::Error::from)?,
            )?));
            Ok(jwk)
        }
        _ => {
            let _ = data;
            let _ = signature;
            Err(Error::UnsupportedAlgorithm)
        }
    }
}

pub fn detached_sign_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
    key: &JWK,
) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat();
    let sig_b64 = sign_bytes_b64(header.algorithm, &signing_input, key)?;
    let jws = header_b64 + ".." + &sig_b64;
    Ok(jws)
}

pub fn generate_header(algorithm: Algorithm, key: &JWK) -> Result<(Header, String), Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_str = base64_encode_json(&header)?;
    Ok((header, header_str))
}

pub fn detached_sign_unencoded_payload_v2(
    algorithm: Algorithm,
    payload: &mut JWSPayload,
    key: &JWK,
) -> Result<String, Error> {
    let (header, header_b64) = generate_header(algorithm, key)?;
    payload.header = header_b64;
    let sig_b64 = sign_bytes_b64_v2(header.algorithm, key, payload)?;
    let jws = payload.header.clone() + ".." + &sig_b64;
    Ok(jws)
}

pub fn prepare_detached_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(Header, Vec<u8>), Error> {
    let header = Header {
        algorithm,
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat().to_vec();
    Ok((header, signing_input))
}

pub fn complete_sign_unencoded_payload(header: &Header, sig_b64: &str) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let jws = header_b64 + ".." + sig_b64;
    Ok(jws)
}

pub fn encode_sign(algorithm: Algorithm, payload: &str, key: &JWK) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        ..Default::default()
    };
    encode_sign_custom_header(payload, key, &header)
}

pub fn encode_sign_custom_header(
    payload: &str,
    key: &JWK,
    header: &Header,
) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let signing_input = header_b64 + "." + &payload_b64;
    let sig_b64 = sign_bytes_b64(header.algorithm, signing_input.as_bytes(), key)?;
    let jws = [signing_input, sig_b64].join(".");
    Ok(jws)
}

pub fn encode_unsigned(payload: &str) -> Result<String, Error> {
    let header = Header {
        algorithm: Algorithm::None,
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    Ok(header_b64 + "." + &payload_b64 + ".")
}

pub fn split_jws(jws: &str) -> Result<(&str, &str, &str), Error> {
    let mut parts = jws.splitn(3, '.');
    Ok(
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (a, b, c),
            _ => return Err(Error::InvalidJWS),
        },
    )
}

pub fn split_detached_jws(jws: &str) -> Result<(&str, &str), Error> {
    let (header_b64, omitted_payload, signature_b64) = split_jws(jws)?;
    if !omitted_payload.is_empty() {
        return Err(Error::InvalidJWS);
    }
    Ok((header_b64, signature_b64))
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecodedJWS {
    pub header: Header,
    pub signing_input: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct JWSPayload {
    pub header: String,
    pub messages: Vec<String>,
    pub sigopts_digest: [u8; 32],
}

/// Decode JWS parts (JOSE header, payload, and signature) into useful values.
/// The payload argument is bytes since it may be unencoded if the b64:false header parameter is used; otherwise it must be a base64url-encoded string. Header and signature are always expected to be base64url-encoded.
/// "crit" (critical) header parameters are checked and disallowed if unrecognized/unsupported.
pub fn decode_jws_parts(
    header_b64: &str,
    payload_enc: &[u8],
    signature_b64: &str,
) -> Result<DecodedJWS, Error> {
    let signature = base64::decode_config(signature_b64, base64::URL_SAFE_NO_PAD)?;
    let header_json = base64::decode_config(header_b64, base64::URL_SAFE_NO_PAD)?;
    let header: Header = serde_json::from_slice(&header_json)?;
    let payload_vec;
    let payload = if header.base64urlencode_payload.unwrap_or(true) {
        payload_vec = base64::decode_config(payload_enc, base64::URL_SAFE_NO_PAD)?;
        payload_vec.as_slice()
    } else {
        payload_enc
    };
    for name in header.critical.iter().flatten() {
        match name.as_str() {
            "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ" | "cty"
            | "crit" => return Err(Error::InvalidCriticalHeader),
            "b64" => {}
            _ => return Err(Error::UnknownCriticalHeader),
        }
    }
    let signing_input = [header_b64.as_bytes(), b".", payload_enc].concat();
    Ok(DecodedJWS {
        header,
        signing_input,
        payload: payload.to_vec(),
        signature,
    })
}

/// Verify a JWS with detached payload. Returns the JWS header on success.
pub fn detached_verify(jws: &str, payload_enc: &[u8], key: &JWK) -> Result<Header, Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok(header)
}

/// Recover a JWK from a JWS and payload, if the algorithm supports that (such as [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r)).
pub fn detached_recover(jws: &str, payload_enc: &[u8]) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    let key = recover(header.algorithm, &signing_input, &signature)?;
    Ok((header, key))
}

pub fn detached_recover_legacy_keccak_es256kr(
    jws: &str,
    payload_enc: &[u8],
) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        mut header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    // Allow ESKeccakK-R misimplementation of ES256K-R, for legacy reasons.
    if header.algorithm != Algorithm::ES256KR {
        return Err(Error::AlgorithmMismatch);
    }
    header.algorithm = Algorithm::ESKeccakKR;
    let key = recover(header.algorithm, &signing_input, &signature)?;
    Ok((header, key))
}

pub fn decode_verify(jws: &str, key: &JWK) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok((header, payload))
}

pub fn decode_unverified(jws: &str) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input: _,
        payload,
        signature: _,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn jws_encode() {
        // https://tools.ietf.org/html/rfc7515#appendix-A.2
        let payload =
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

        use serde_json::json;
        // https://tools.ietf.org/html/rfc7515#page-41
        let key: JWK = serde_json::from_value(json!({"kty":"RSA",
         "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
         "e":"AQAB",
         "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
         "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc", "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
         "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
         "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
         "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
        }))
        .unwrap();

        // https://tools.ietf.org/html/rfc7515#page-43
        let jws = encode_sign(Algorithm::RS256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw");

        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn secp256k1_sign_verify() {
        let key = JWK::generate_secp256k1().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256K, data, &key).unwrap();
        verify_bytes(Algorithm::ES256K, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256K, bad_data, &key, &sig).unwrap_err();

        // ES256K-R
        let key = JWK {
            algorithm: Some(Algorithm::ES256KR),
            ..key
        };
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();

        // Test recovery
        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ES256KR, data, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &recovered_key, &sig).unwrap();
        let other_key = JWK::generate_secp256k1().unwrap();
        verify_bytes(Algorithm::ES256KR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "eip")]
    fn keccak_sign_verify() {
        let key = JWK::generate_secp256k1().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        // ESKeccakK-R
        let key = JWK {
            algorithm: Some(Algorithm::ESKeccakKR),
            ..key
        };

        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        let other_key = JWK::generate_secp256k1().unwrap();
        // TODO check the error type
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();

        // Test recovery (ESKeccakK-R)
        let sig = sign_bytes(Algorithm::ESKeccakKR, data, &key).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ESKeccakKR, data, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &recovered_key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "p256")]
    fn p256_sign_verify() {
        let key = JWK::generate_p256().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256, data, &key).unwrap();
        verify_bytes(Algorithm::ES256, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256, bad_data, &key, &sig).unwrap_err();

        let key: JWK =
            serde_json::from_str(include_str!("../../tests/secp256r1-2021-03-18.json")).unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.rJzO6MmTNS8Tn-L3baIf9_2Jr9OoK8E06MxJtofz8xMUGSom6eRUmWGZ7oQVjgP3HogOD80miTvuvKTWa54Nvw");
        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "p384")]
    fn p384_sign_verify() {
        let key = JWK::generate_p384().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES384, data, &key).unwrap();
        verify_bytes(Algorithm::ES384, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES384, bad_data, &key, &sig).unwrap_err();

        let key: JWK =
            serde_json::from_str(include_str!("../../tests/secp384r1-2022-05-10.json")).unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES384, payload, &key).unwrap();
        dbg!(&jws);
        decode_verify(&jws, &key).unwrap();

        const JWS: &str = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.2vpBSFN7DxuS57epgq_e7-NyNiJ5eOOrExmi65C_wtZOC2-9i6fVvMnfUig7QmgiirznAg1wr_b7_kH-bbMCI5Pdf8pAnxQg3LL9I9OhzttyG06qAl9L7BE6aNS-aqnf";
        decode_verify(&JWS, &key).unwrap();
    }
}
