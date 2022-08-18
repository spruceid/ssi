use std::collections::HashMap as Map;
#[cfg(feature = "keccak-hash")]
use std::convert::TryFrom;

use async_trait::async_trait;

const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];

// use crate::did::{VerificationMethod, VerificationMethodMap};
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedData;
use caips::caip10::BlockchainAccountId;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, resolve_vm, DIDResolver};
use ssi_json_ld::{urdna2015, ContextLoader};
use ssi_jwk::{Algorithm, Base64urlUInt, ECParams, Params as JWKParams, JWK};

use super::*;

pub struct RsaSignature2018;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for RsaSignature2018 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        verify(proof, document, resolver, context_loader).await
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        verify(proof, document, resolver, context_loader).await
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
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign_nojws(
            document,
            options,
            context_loader,
            key,
            "Ed25519Signature2020",
            Algorithm::EdDSA,
            ssi_json_ld::W3ID_ED2020_V1_CONTEXT,
            extra_proof_properties,
        )
        .await
    }
    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        verify_nojws(proof, document, resolver, context_loader, Algorithm::EdDSA).await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare_nojws(
            document,
            options,
            context_loader,
            public_key,
            "Ed25519Signature2020",
            Algorithm::EdDSA,
            ssi_json_ld::W3ID_ED2020_V1_CONTEXT,
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        verify(proof, document, resolver, context_loader).await
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != Algorithm::ES256KR {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        let has_context = document_has_context(document, ssi_json_ld::W3ID_ESRS2020_V2_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_ESRS2020_V2_CONTEXT])
            },
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, Algorithm::ES256KR, context_loader).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let has_context = document_has_context(document, ssi_json_ld::W3ID_ESRS2020_V2_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_ESRS2020_V2_CONTEXT])
            },
            ..Proof::new("EcdsaSecp256k1RecoverySignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, Algorithm::ES256KR, context_loader).await
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
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, proof, context_loader).await?;
        let (_header, jwk) = ssi_jws::detached_recover(jws, &message)?;
        let mut warnings = VerificationWarnings::default();
        if let Err(_e) = vm.match_jwk(&jwk) {
            // Legacy mode: allow using Keccak-256 instead of SHA-256
            let (_header, jwk) = ssi_jws::detached_recover_legacy_keccak_es256kr(jws, &message)?;
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
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::EdBlake2b, context_loader).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            ..Proof::new("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::EdBlake2b, context_loader).await
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
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            ..Proof::new("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        sign_proof(document, proof, key, Algorithm::ESBlake2b, context_loader).await
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            ..Proof::new("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
                .with_options(options)
                .with_properties(props)
        };
        prepare_proof(document, proof, Algorithm::ESBlake2b, context_loader).await
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
        context_loader: &mut ContextLoader,
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
        let typed_data =
            TypedData::from_document_and_options(document, &proof, context_loader).await?;
        let bytes = typed_data.bytes()?;
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(ssi_jwk::Error::KeyTypeNotImplemented.into()),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature =
            signing_key.try_sign(&bytes).map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] += 27;
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EIP712VM_CONTEXT.clone()]),
            ..Proof::new("Eip712Signature2021")
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
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)
            .map_err(ssi_jwk::Error::from)?;
        let sig =
            k256::ecdsa::recoverable::Signature::new(&sig, rec_id).map_err(ssi_jwk::Error::from)?;
        // TODO this step needs keccak-hash, may need better features management
        let recovered_key = sig
            .recover_verify_key(&bytes)
            .map_err(ssi_jwk::Error::from)?;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
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
        _context_loader: &mut ContextLoader,
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
            context: serde_json::json!(ssi_json_ld::EIP712SIG_V1_CONTEXT),
            ..Proof::new("EthereumEip712Signature2021")
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
        let sig: k256::ecdsa::recoverable::Signature =
            signing_key.try_sign(&bytes).map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] += 27;
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _context_loader: &mut ContextLoader,
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
            context: serde_json::json!(ssi_json_ld::EIP712SIG_V1_CONTEXT),
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
        _context_loader: &mut ContextLoader,
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
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)
            .map_err(ssi_jwk::Error::from)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let sig =
            k256::ecdsa::recoverable::Signature::new(&sig, rec_id).map_err(ssi_jwk::Error::from)?;
        let typed_data = TypedData::from_document_and_options_json(document, proof).await?;
        let bytes = typed_data.bytes()?;
        let recovered_key = sig
            .recover_verify_key(&bytes)
            .map_err(ssi_jwk::Error::from)?;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
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
        context_loader: &mut ContextLoader,
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
        let signing_string =
            string_from_document_and_options(document, &proof, context_loader).await?;
        let hash = ssi_crypto::hashes::keccak::prefix_personal_message(&signing_string);
        let ec_params = match &key.params {
            JWKParams::EC(ec) => ec,
            _ => return Err(ssi_jwk::Error::KeyTypeNotImplemented.into()),
        };
        let secret_key = k256::SecretKey::try_from(ec_params)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature =
            signing_key.try_sign(&hash).map_err(ssi_jwk::Error::from)?;
        let sig_bytes = &mut sig.as_ref().to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] += 27;
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        proof.proof_value = Some(sig_hex);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([EPSIG_CONTEXT.clone()]),
            ..Proof::new("EthereumPersonalSignature2021")
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
        let rec_id = k256::ecdsa::recoverable::Id::try_from(dec_sig[64] % 27)
            .map_err(ssi_jwk::Error::from)?;
        let sig = k256::ecdsa::Signature::try_from(&dec_sig[..64]).map_err(ssi_jwk::Error::from)?;
        let sig =
            k256::ecdsa::recoverable::Signature::new(&sig, rec_id).map_err(ssi_jwk::Error::from)?;
        let signing_string =
            string_from_document_and_options(document, proof, context_loader).await?;
        let hash = ssi_crypto::hashes::keccak::prefix_personal_message(&signing_string);
        let recovered_key = sig
            .recover_verify_key(&hash)
            .map_err(ssi_jwk::Error::from)?;
        let jwk = JWK {
            params: JWKParams::EC(ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
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
    let doc_dataset_normalized = urdna2015::normalize(&doc_dataset)?;
    let doc_normalized = doc_dataset_normalized.to_nquads()?;
    let sigopts_dataset_normalized = urdna2015::normalize(&sigopts_dataset)?;
    let sigopts_normalized = sigopts_dataset_normalized.to_nquads()?;
    let msg = ["", &sigopts_normalized, &doc_normalized].join("\n");
    let data = ssi_tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

async fn micheline_from_document_and_options_jcs(
    document: &(dyn LinkedDataDocument + Sync),
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let mut doc_value = document.to_value()?;
    let doc_obj = doc_value
        .as_object_mut()
        .ok_or(ssi_json_ld::Error::ExpectedObject)?;
    let mut proof_value = serde_json::to_value(proof)?;
    let proof_obj = proof_value
        .as_object_mut()
        .ok_or(ssi_json_ld::Error::ExpectedObject)?;
    proof_obj.remove("proofValue");
    doc_obj.insert("proof".to_string(), proof_value);
    let msg = serde_jcs::to_string(&doc_value)?;
    let data = ssi_tzkey::encode_tezos_signed_message(&msg)?;
    Ok(data)
}

#[cfg(feature = "keccak-hash")]
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
            ..Proof::new("TezosSignature2021")
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

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            ..Proof::new("TezosSignature2021")
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
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for TezosJcsSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
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
            ..Proof::new("TezosJcsSignature2021")
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

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _context_loader: &mut ContextLoader,
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
        _context_loader: &mut ContextLoader,
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

pub struct SolanaSignature2021;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for SolanaSignature2021 {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let mut proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("SolanaSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof, context_loader).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let sig = ssi_jws::sign_bytes(Algorithm::EdDSA, &bytes, key)?;
        let sig_b58 = bs58::encode(&sig).into_string();
        proof.proof_value = Some(sig_b58);
        Ok(proof)
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("SolanaSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof, context_loader).await?;
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
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, proof, context_loader).await?;
        let tx = crate::soltx::LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let sig = bs58::decode(&sig_b58).into_vec()?;
        Ok(ssi_jws::verify_bytes_warnable(
            Algorithm::EdDSA,
            &bytes,
            &key,
            &sig,
        )?)
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
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, &proof, context_loader).await?;
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
        context_loader: &mut ContextLoader,
        _public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new("AleoSignature2021")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof, context_loader).await?;
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
        context_loader: &mut ContextLoader,
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
        let message = to_jws_payload(document, proof, context_loader).await?;
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        sign(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        prepare(
            document,
            options,
            resolver,
            context_loader,
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
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        verify(proof, document, resolver, context_loader).await
    }
    async fn complete(
        &self,
        preparation: ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        complete(preparation, signature).await
    }
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
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        self.validate_key_and_algorithm(key, algorithm)?;
        let has_context = document_has_context(document, ssi_json_ld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_JWS2020_V1_CONTEXT])
            },
            ..Proof::new("JsonWebSignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, algorithm, context_loader).await
    }
    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let algorithm = public_key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        self.validate_key_and_algorithm(public_key, algorithm)?;
        let has_context = document_has_context(document, ssi_json_ld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_JWS2020_V1_CONTEXT])
            },
            ..Proof::new("JsonWebSignature2020")
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, algorithm, context_loader).await
    }
    async fn verify(
        &self,
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
        let (header_b64, signature_b64) = ssi_jws::split_detached_jws(jws)?;
        let message = to_jws_payload(document, proof, context_loader).await?;
        let ssi_jws::DecodedJWS {
            header,
            signing_input,
            payload: _,
            signature,
        } = ssi_jws::decode_jws_parts(header_b64, &message, signature_b64)?;
        // Redundant early algorithm check before expensive key lookup and signature verification.
        self.validate_algorithm(header.algorithm)?;
        let key = resolve_key(verification_method, resolver).await?;
        self.validate_key_and_algorithm(&key, header.algorithm)?;
        Ok(ssi_jws::verify_bytes_warnable(
            header.algorithm,
            &signing_input,
            &key,
            &signature,
        )?)
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
            Algorithm::ES384 => (),
            Algorithm::PS256 => (),
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        }
        Ok(())
    }
    // https://w3c-ccg.github.io/lds-jws2020/#jose-conformance
    fn validate_key_and_algorithm(&self, key: &JWK, algorithm: Algorithm) -> Result<(), Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != algorithm {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        match &key.params {
            JWKParams::RSA(_) => match algorithm {
                Algorithm::PS256 => (),
                _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
            },
            JWKParams::EC(ec_params) => {
                match &ec_params
                    .curve
                    .as_ref()
                    .ok_or(ssi_jwk::Error::MissingCurve)?[..]
                {
                    "secp256k1" => match algorithm {
                        Algorithm::ES256K => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    "P-256" => match algorithm {
                        Algorithm::ES256 => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    "P-384" => match algorithm {
                        Algorithm::ES384 => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    _ => {
                        return Err(Error::UnsupportedCurve);
                    }
                }
            }
            JWKParams::OKP(okp_params) => match &okp_params.curve[..] {
                "Ed25519" => match algorithm {
                    Algorithm::EdDSA => (),
                    _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
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
