use super::super::*;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use std::collections::HashMap as Map;

pub struct SolanaSignature2021;
impl SolanaSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let mut proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::SolanaSignature2021)
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

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::SolanaSignature2021)
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

    pub(crate) async fn verify(
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
