use super::super::*;
use async_trait::async_trait;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, Params as JWKParams, JWK};
use std::collections::HashMap as Map;

#[cfg(feature = "rsa")]
pub struct RsaSignature2018;
#[cfg(feature = "rsa")]
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

#[cfg(feature = "ed25519")]
pub struct Ed25519Signature2018;
#[cfg(feature = "ed25519")]
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

#[cfg(feature = "ed25519")]
pub struct Ed25519Signature2020;
#[cfg(feature = "ed25519")]
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

#[cfg(feature = "secp256k1")]
pub struct EcdsaSecp256k1Signature2019;
#[cfg(feature = "secp256k1")]
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

#[cfg(feature = "secp256k1")]
pub struct EcdsaSecp256k1RecoverySignature2020;
#[cfg(feature = "secp256k1")]
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
#[cfg(feature = "secp256r1")]
pub struct EcdsaSecp256r1Signature2019;
#[cfg(feature = "secp256r1")]
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
            _ => return Err(Error::UnsupportedCurve),
        }
        Ok(())
    }
}
