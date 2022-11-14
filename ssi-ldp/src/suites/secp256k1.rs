use super::super::*;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, JWK};
use std::collections::HashMap as Map;

#[cfg(feature = "secp256k1")]
pub struct EcdsaSecp256k1RecoverySignature2020;
#[cfg(feature = "secp256k1")]
impl EcdsaSecp256k1RecoverySignature2020 {
    pub(crate) async fn sign(
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
            ..Proof::new(ProofSuiteType::EcdsaSecp256k1RecoverySignature2020)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, Algorithm::ES256KR, context_loader).await
    }

    pub(crate) async fn prepare(
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
            ..Proof::new(ProofSuiteType::EcdsaSecp256k1RecoverySignature2020)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, Algorithm::ES256KR, context_loader).await
    }

    pub(crate) async fn verify(
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
