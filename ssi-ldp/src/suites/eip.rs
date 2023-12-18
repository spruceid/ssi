use super::super::*;
use crate::eip712::TypedData;
use k256::ecdsa::VerifyingKey;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{ECParams, Params as JWKParams, JWK};
use std::collections::HashMap as Map;

pub struct Eip712Signature2021;
impl Eip712Signature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let mut proof = Proof {
            context: serde_json::json!([EIP712VM_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::Eip712Signature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let typed_data =
            TypedData::from_document_and_options(document, &proof, context_loader).await?;
        let bytes = typed_data.bytes()?;
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(ssi_jwk::Error::KeyTypeNotImplemented.into()),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(bytes))
            .map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes.push(rec_id.to_byte() + 27);
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EIP712VM_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::Eip712Signature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let typed_data =
            TypedData::from_document_and_options(document, &proof, context_loader).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::TypedData(typed_data),
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
        let typed_data =
            TypedData::from_document_and_options(document, proof, context_loader).await?;
        let bytes = typed_data.bytes()?;
        if !sig_hex.starts_with("0x") {
            return Err(Error::HexString);
        }
        let dec_sig = hex::decode(&sig_hex[2..])?;
        let rec_id =
            k256::ecdsa::RecoveryId::try_from(dec_sig[64] % 27).map_err(ssi_jwk::Error::from)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let recovered_key = VerifyingKey::recover_from_digest(
            sha3::Keccak256::new_with_prefix(bytes),
            &sig,
            rec_id,
        )
        .map_err(ssi_jwk::Error::from)?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
    }
}

pub struct EthereumEip712Signature2021;
impl EthereumEip712Signature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        // TODO: conform to spec: no domain
        let mut props = extra_proof_properties.clone();
        if let Some(ref eip712_domain) = options.eip712_domain {
            let info = serde_json::to_value(eip712_domain.clone())?;
            props
                .get_or_insert(Map::new())
                .insert("eip712Domain".to_string(), info);
        }
        let mut proof = Proof {
            context: serde_json::json!(ssi_json_ld::EIP712SIG_V1_CONTEXT),
            ..Proof::new(ProofSuiteType::EthereumEip712Signature2021)
                .with_options(options)
                .with_properties(props)
        };
        let typed_data = TypedData::from_document_and_options_json(document, &proof).await?;
        let bytes = typed_data.bytes()?;
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(ssi_jwk::Error::KeyTypeNotImplemented.into()),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(bytes))
            .map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes.push(rec_id.to_byte() + 27);
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
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
            context: serde_json::json!(ssi_json_ld::EIP712SIG_V1_CONTEXT),
            ..Proof::new(ProofSuiteType::EthereumEip712Signature2021)
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

    pub(crate) async fn verify(
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
        let rec_id =
            k256::ecdsa::RecoveryId::try_from(dec_sig[64] % 27).map_err(ssi_jwk::Error::from)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let typed_data = TypedData::from_document_and_options_json(document, proof).await?;
        let bytes = typed_data.bytes()?;
        let recovered_key = VerifyingKey::recover_from_digest(
            sha3::Keccak256::new_with_prefix(bytes),
            &sig,
            rec_id,
        )
        .map_err(ssi_jwk::Error::from)?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
    }
}

pub struct EthereumPersonalSignature2021;
impl EthereumPersonalSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let mut proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::EthereumPersonalSignature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let signing_string =
            string_from_document_and_options(document, &proof, context_loader).await?;
        let hash = ssi_crypto::hashes::keccak::prefix_personal_message(&signing_string);
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(ssi_jwk::Error::KeyTypeNotImplemented.into()),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(hash))
            .map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes.push(rec_id.to_byte() + 27);
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::EthereumPersonalSignature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let signing_string =
            string_from_document_and_options(document, &proof, context_loader).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::EthereumPersonalMessage {
                ethereum_personal_message: signing_string,
            },
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
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
        let rec_id =
            k256::ecdsa::RecoveryId::try_from(dec_sig[64] % 27).map_err(ssi_jwk::Error::from)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let signing_string =
            string_from_document_and_options(document, proof, context_loader).await?;
        let hash = ssi_crypto::hashes::keccak::prefix_personal_message(&signing_string);
        let recovered_key =
            VerifyingKey::recover_from_digest(sha3::Keccak256::new_with_prefix(hash), &sig, rec_id)
                .map_err(ssi_jwk::Error::from)?;
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
        vm.match_jwk(&jwk)?;
        Ok(Default::default())
    }
}

async fn string_from_document_and_options(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
    context_loader: &mut ContextLoader,
) -> Result<String, Error> {
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
    let msg = sigopts_normalized + "\n" + &doc_normalized;
    Ok(msg)
}
