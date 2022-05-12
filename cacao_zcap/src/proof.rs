use std::collections::HashMap;

use async_trait::async_trait;
use cacaos::siwe_cacao::SignInWithEthereum;
use serde_json::Value;
use ssi::{
    did_resolve::DIDResolver,
    error::Error as SSIError,
    jwk::JWK,
    jws::VerificationWarnings,
    ldp::{LinkedDataDocument, ProofPreparation, ProofSuite},
    vc::{LinkedDataProofOptions, Proof},
    zcap::Delegation,
};

use crate::{
    translation::zcap_to_cacao::zcap_to_cacao, CacaoZcapExtraProps, CacaoZcapProofExtraProps,
};

/// [CacaoZcapProof2022](https://demo.didkit.dev/2022/cacao-zcap/#CacaoZcapProof2022) proof suite
/// implementation
pub struct CacaoZcapProof2022;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for CacaoZcapProof2022 {
    async fn sign(
        &self,
        _document: &(dyn LinkedDataDocument + Sync),
        _options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _key: &JWK,
        _extra_proof_properties: Option<HashMap<String, Value>>,
    ) -> Result<Proof, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let has_context = document_has_context(document, CONTEXT_URL_V1)?;
        let mut proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                json!([CONTEXT_URL_V1])
            },
            ..Proof::new(PROOF_TYPE_2022)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        let sig = sign(&message, &key)?;
        let sig_mb = multibase::encode(multibase::Base::Base16Lower, sig);
        proof.proof_value = Some(sig_mb);
        Ok(proof)
        */
    }

    async fn prepare(
        &self,
        _document: &(dyn LinkedDataDocument + Sync),
        _options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _public_key: &JWK,
        _extra_proof_properties: Option<HashMap<String, Value>>,
    ) -> Result<ProofPreparation, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new(PROOF_TYPE_2022)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
        })
        */
    }

    async fn complete(
        &self,
        _preparation: ProofPreparation,
        _signature: &str,
    ) -> Result<Proof, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
        */
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        _resolver: &dyn DIDResolver,
    ) -> Result<VerificationWarnings, SSIError> {
        use anyhow::{anyhow, Context};

        // Note: from_property_set_opt is called again in zcap_to_cacao; this seems hard to avoid.
        let proof_extraprops =
            CacaoZcapProofExtraProps::from_property_set_opt(proof.property_set.clone())
                .context("Unable to convert extra proof properties")?;
        let mut doc = document
            .to_value()
            .context("Unable to convert zcap document to Value")?;
        doc["proof"] = proof
            .to_value()
            .context("Unable to convert zcap proof to Value")?;
        let zcap: Delegation<(), CacaoZcapExtraProps> = serde_json::from_value(doc)
            .context("Unable to convert zcap from Value to Delegation")?;
        let payload_type = zcap.property_set.cacao_payload_type.as_str();
        let signature_type = proof_extraprops.cacao_signature_type.as_str();

        let cacao = match (payload_type, signature_type) {
            ("eip4361", "eip191") => zcap_to_cacao::<SignInWithEthereum>(&zcap)
                .context("Unable to convert zcap to SIWE CACAO")?,
            (header_type, sig_type) => {
                return Err(anyhow!(
                    "Unexpected payload/signature type '{}-{}'",
                    header_type,
                    sig_type
                )
                .into());
            }
        };
        cacao.verify().await.context("Unable to verify CACAO")?;

        /* TODO: check VM
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(SSIError::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver)
            .await
            .context("Unable to resolve verification method")?;
        if vm.type_ != "EcdsaSecp256k1RecoveryMethod2020" {
            return Err(anyhow!("Unexpected verification method type").into());
        }
        let account_id: BlockchainAccountId = vm
            .blockchain_account_id
            .ok_or(anyhow!("Expected blockchainAccountId property"))?
            .parse()
            .context("Unable to parse blockchainAccountId property")?;
        // let message = to_jws_payload(document, proof).await?;
        // crate::aleo::verify(&message, &account_id.account_address, &sig)?;
        */
        Ok(Default::default())
    }
}
