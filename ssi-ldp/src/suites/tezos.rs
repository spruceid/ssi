use super::super::*;
use serde_json::Value;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::{urdna2015, ContextLoader};
use ssi_jwk::{Algorithm, JWK};
use std::collections::HashMap as Map;

const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
impl Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::EdBlake2b {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
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
            ..Proof::new(ProofSuiteType::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::EdBlake2b, context_loader).await
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
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
            ..Proof::new(ProofSuiteType::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::EdBlake2b, context_loader).await
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, proof, context_loader).await?;
        ssi_jws::detached_verify(jws, &message, &jwk)?;
        Ok(Default::default())
    }
}

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz3` addresses.
pub struct P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
impl P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::ESBlake2b {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
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
            ..Proof::new(ProofSuiteType::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::ESBlake2b, context_loader).await
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
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
            ..Proof::new(ProofSuiteType::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::ESBlake2b, context_loader).await
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, proof, context_loader).await?;
        ssi_jws::detached_verify(jws, &message, &jwk)?;
        Ok(Default::default())
    }
}

async fn micheline_from_document_and_options(
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
    let doc_dataset_normalized = urdna2015::normalize(doc_dataset.quads().map(QuadRef::from));
    let doc_normalized = doc_dataset_normalized.into_nquads();
    let sigopts_dataset_normalized =
        urdna2015::normalize(sigopts_dataset.quads().map(QuadRef::from));
    let sigopts_normalized = sigopts_dataset_normalized.into_nquads();
    let msg = ["", &sigopts_normalized, &doc_normalized].join("\n");
    let data = ssi_tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

async fn micheline_from_document_and_options_jcs(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let mut doc_value = document.to_value()?;
    let doc_obj = doc_value.as_object_mut().ok_or(Error::ExpectedJsonObject)?;
    let mut proof_value = serde_json::to_value(proof)?;
    let proof_obj = proof_value
        .as_object_mut()
        .ok_or(Error::ExpectedJsonObject)?;
    proof_obj.remove("proofValue");
    doc_obj.insert("proof".to_string(), proof_value);
    let msg = serde_jcs::to_string(&doc_value)?;
    let data = ssi_tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

pub struct TezosSignature2021;
impl TezosSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
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
            ..Proof::new(ProofSuiteType::TezosSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        let micheline =
            micheline_from_document_and_options(document, &proof, context_loader).await?;
        let sig = ssi_jws::sign_bytes(algorithm, &micheline, key)?;
        let mut sig_prefixed = Vec::new();
        let prefix: &[u8] = match algorithm {
            Algorithm::EdBlake2b => &EDSIG_PREFIX,
            Algorithm::ESBlake2bK => &SPSIG_PREFIX,
            Algorithm::ESBlake2b => &P2SIG_PREFIX,
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        };
        sig_prefixed.extend_from_slice(prefix);
        sig_prefixed.extend_from_slice(&sig);
        let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
        proof.proof_value = Some(sig_bs58);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
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
            ..Proof::new(ProofSuiteType::TezosSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        let micheline =
            micheline_from_document_and_options(document, &proof, context_loader).await?;
        let micheline_string = hex::encode(micheline);
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Micheline {
                micheline: micheline_string,
            },
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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

        let (algorithm, sig) = ssi_tzkey::decode_tzsig(sig_bs58)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "TezosMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }

        let micheline =
            micheline_from_document_and_options(document, proof, context_loader).await?;
        let account_id_opt: Option<BlockchainAccountId> = match vm.blockchain_account_id {
            Some(account_id_string) => Some(account_id_string.parse()?),
            None => None,
        };

        // VM must have either publicKeyJwk or blockchainAccountId.
        let warnings = if let Some(vm_jwk) = vm.public_key_jwk {
            // If VM has publicKey, use that to verify the signature.
            ssi_jws::verify_bytes_warnable(algorithm, &micheline, &vm_jwk, &sig)?
            // Note: VM blockchainAccountId is ignored in this case.
        } else if let Some(account_id) = account_id_opt {
            // VM does not have publicKeyJwk: proof must have public key
            if let Some(proof_jwk) = proof_jwk_opt {
                // Proof has public key: verify it with blockchainAccountId,
                account_id.verify(&proof_jwk)?;
                // and verify the signature.
                ssi_jws::verify_bytes_warnable(algorithm, &micheline, &proof_jwk, &sig)?
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
impl TezosJcsSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        let tzpk = ssi_tzkey::jwk_to_tezos_key(&key.to_public())?;
        let pkmb = "z".to_string() + &tzpk;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyMultibase".to_string(), Value::String(pkmb));
        let mut proof = Proof {
            context: TZJCSVM_CONTEXT.clone(),
            ..Proof::new(ProofSuiteType::TezosJcsSignature2021)
                .with_options(options)
                .with_properties(props)
        };
        let micheline =
            micheline_from_document_and_options(document, &proof, context_loader).await?;
        let sig = ssi_jws::sign_bytes(algorithm, &micheline, key)?;
        let mut sig_prefixed = Vec::new();
        let prefix: &[u8] = match algorithm {
            Algorithm::EdBlake2b => &EDSIG_PREFIX,
            Algorithm::ESBlake2bK => &SPSIG_PREFIX,
            Algorithm::ESBlake2b => &P2SIG_PREFIX,
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        };
        sig_prefixed.extend_from_slice(prefix);
        sig_prefixed.extend_from_slice(&sig);
        let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
        proof.proof_value = Some(sig_bs58);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        // TODO: dereference VM URL to check if VM already contains public key.
        // "z" is multibase for base58. Usually publicKeyMultibase is used with multicodec, but
        // here we use it for Tezos-style base58 key representation.
        let pkmb = "z".to_string() + &ssi_tzkey::jwk_to_tezos_key(&public_key.to_public())?;
        let mut props = extra_proof_properties.clone();
        props
            .get_or_insert(Map::new())
            .insert("publicKeyMultibase".to_string(), Value::String(pkmb));

        let proof = Proof {
            context: TZJCSVM_CONTEXT.clone(),
            ..Proof::new(ProofSuiteType::TezosJcsSignature2021)
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

    pub(crate) async fn verify(
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

        let (algorithm, sig) = ssi_tzkey::decode_tzsig(sig_bs58)?;
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
            ssi_jws::verify_bytes_warnable(algorithm, &micheline, &vm_jwk, &sig)?
            // Note: VM blockchainAccountId is ignored in this case.
        } else if let Some(account_id) = account_id_opt {
            // VM does not have publicKeyJwk: proof must have public key
            if let Some(proof_pkmb) = proof_pkmb_opt {
                if !proof_pkmb.starts_with('z') {
                    return Err(Error::ExpectedMultibaseZ);
                }
                proof_jwk_opt = Some(ssi_tzkey::jwk_from_tezos_key(&proof_pkmb[1..])?);
            }
            if let Some(proof_jwk) = proof_jwk_opt {
                // Proof has public key: verify it with blockchainAccountId,
                account_id.verify(&proof_jwk)?;
                // and verify the signature.
                ssi_jws::verify_bytes_warnable(algorithm, &micheline, &proof_jwk, &sig)?
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
