use std::collections::HashMap as Map;
use std::{convert::TryFrom, str::FromStr};

use chrono::prelude::*;

use super::*;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_dids::VerificationRelationship as ProofPurpose;
use ssi_json_ld::{json_to_dataset, ContextLoader, Error as JsonLdError};

#[macro_export]
macro_rules! assert_local {
    ($cond:expr) => {
        if !$cond {
            return false;
        }
    };
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "@context")]
    // TODO: use consistent types for context
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<ProofPurpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Note: ld-proofs specifies verificationMethod as a "set of parameters",
    // but all examples use a single string.
    pub verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>, // ISO 8601
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl Proof {
    pub fn new(type_: &str) -> Self {
        Self {
            type_: type_.to_string(),
            ..Self::default()
        }
    }

    pub fn with_options(self, options: &LinkedDataProofOptions) -> Self {
        Self {
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options
                .verification_method
                .clone()
                .map(|uri| uri.to_string()),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            ..self
        }
    }

    pub fn with_properties(self, properties: Option<Map<String, Value>>) -> Self {
        Self {
            property_set: properties,
            ..self
        }
    }

    /// Check that a proof matches the given options.
    #[allow(clippy::ptr_arg)]
    pub fn matches_options(&self, options: &LinkedDataProofOptions) -> bool {
        if let Some(ref verification_method) = options.verification_method {
            assert_local!(
                self.verification_method.as_ref() == Some(&verification_method.to_string())
            );
        }
        if let Some(created) = self.created {
            assert_local!(options.created.unwrap_or_else(now_ms) >= created);
        } else {
            return false;
        }
        if let Some(ref challenge) = options.challenge {
            assert_local!(self.challenge.as_ref() == Some(challenge));
        }
        if let Some(ref domain) = options.domain {
            assert_local!(self.domain.as_ref() == Some(domain));
        }
        if let Some(ref proof_purpose) = options.proof_purpose {
            assert_local!(self.proof_purpose.as_ref() == Some(proof_purpose));
        }
        if let Some(ref type_) = options.type_ {
            assert_local!(&self.type_ == type_);
        }
        true
    }

    /// Check that a proof's verification method belongs to the given set.
    pub fn matches_vms(&self, allowed_vms: &[String]) -> bool {
        if let Some(vm) = self.verification_method.as_ref() {
            assert_local!(allowed_vms.contains(vm));
        }
        true
    }

    /// Check that a proof matches the given options and allowed verification methods.
    ///
    /// Equivalent to [Self::matches_options] and [Self::matches_vm].
    #[allow(clippy::ptr_arg)]
    pub fn matches(&self, options: &LinkedDataProofOptions, allowed_vms: &Vec<String>) -> bool {
        self.matches_options(options) && self.matches_vms(allowed_vms)
    }

    pub async fn verify(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        LinkedDataProofs::verify(self, document, resolver, context_loader)
            .await
            .into()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl LinkedDataDocument for Proof {
    fn get_contexts(&self) -> Result<Option<String>, Error> {
        Ok(None)
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
        context_loader: &mut ContextLoader,
    ) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.jws = None;
        copy.proof_value = None;
        let json = serde_json::to_string(&copy)?;
        let more_contexts = match parent {
            Some(parent) => parent.get_contexts()?,
            None => None,
        };
        let dataset =
            json_to_dataset(&json, more_contexts.as_ref(), false, None, context_loader).await?;
        verify_proof_consistency(self, &dataset)?;
        Ok(dataset)
    }

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
    }
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
/// Options for specifying how the LinkedDataProof is created.
/// Reference: vc-http-api
pub struct LinkedDataProofOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    /// The type of the proof. Default is an appropriate proof type corresponding to the verification method.
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The URI of the verificationMethod used for the proof. If omitted a default
    /// assertionMethod will be used.
    pub verification_method: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The purpose of the proof. If omitted "assertionMethod" will be used.
    pub proof_purpose: Option<ProofPurpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The date of the proof. If omitted system time will be used.
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The challenge of the proof.
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The domain of the proof.
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Checks to perform
    pub checks: Option<Vec<Check>>,
    /// Metadata for EthereumEip712Signature2021 (not standard in vc-http-api)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "eip")]
    pub eip712_domain: Option<crate::eip712::ProofInfo>,
    #[cfg(not(feature = "eip"))]
    pub eip712_domain: Option<()>,
}

impl Default for LinkedDataProofOptions {
    fn default() -> Self {
        Self {
            verification_method: None,
            proof_purpose: Some(ProofPurpose::default()),
            created: Some(crate::now_ms()),
            challenge: None,
            domain: None,
            checks: Some(vec![Check::Proof]),
            eip712_domain: None,
            type_: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Check {
    Proof,
    #[serde(rename = "JWS")]
    JWS,
    Status,
}

impl FromStr for Check {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "proof" => Ok(Self::Proof),
            "JWS" => Ok(Self::JWS),
            "credentialStatus" => Ok(Self::Status),
            _ => Err(Error::UnsupportedCheck),
        }
    }
}

impl TryFrom<String> for Check {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<Check> for String {
    fn from(check: Check) -> String {
        match check {
            Check::Proof => "proof".to_string(),
            Check::JWS => "JWS".to_string(),
            Check::Status => "credentialStatus".to_string(),
        }
    }
}

/// Verify alignment of proof options in JSON with RDF terms
fn verify_proof_consistency(proof: &Proof, dataset: &DataSet) -> Result<(), Error> {
    use ssi_json_ld::rdf;
    let mut graph_ref = dataset.default_graph.as_ref();

    let type_triple = graph_ref
        .take(
            None,
            Some(&rdf::Predicate::IRIRef(rdf::IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
            ))),
            None,
        )
        .ok_or(Error::MissingType)?;
    let type_iri = match type_triple.object {
        rdf::Object::IRIRef(rdf::IRIRef(ref iri)) => iri,
        _ => {
            return Err(Error::JsonLd(JsonLdError::UnexpectedTriple(
                type_triple.clone(),
            )))
        }
    };
    match (proof.type_.as_str(), type_iri.as_str()) {
        ("RsaSignature2018", "https://w3id.org/security#RsaSignature2018") => (),
        ("Ed25519Signature2018", "https://w3id.org/security#Ed25519Signature2018") => (),
        ("Ed25519Signature2020", "https://w3id.org/security#Ed25519Signature2020") => (),
        ("EcdsaSecp256k1Signature2019", "https://w3id.org/security#EcdsaSecp256k1Signature2019") => (),
        ("EcdsaSecp256r1Signature2019", "https://w3id.org/security#EcdsaSecp256r1Signature2019") => (),
        ("EcdsaSecp256k1RecoverySignature2020", "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoverySignature2020") => (),
        ("EcdsaSecp256k1RecoverySignature2020", "https://w3id.org/security#EcdsaSecp256k1RecoverySignature2020") => (),
        ("JsonWebSignature2020", "https://w3id.org/security#JsonWebSignature2020") => (),
        ("EthereumPersonalSignature2021", "https://demo.spruceid.com/ld/epsig/EthereumPersonalSignature2021") => (),
        ("EthereumPersonalSignature2021", "https://w3id.org/security#EthereumPersonalSignature2021") => (),
        ("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021", "https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021") => (),
        ("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021", "https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021") => (),
        ("Eip712Signature2021", "https://w3id.org/security#Eip712Signature2021") => (),
        ("TezosSignature2021", "https://w3id.org/security#TezosSignature2021") => (),
        ("TezosJcsSignature2021", "https://w3id.org/security#TezosJcsSignature2021") => (),
        ("AleoSignature2021", "https://w3id.org/security#AleoSignature2021") => (),
        ("SolanaSignature2021", "https://w3id.org/security#SolanaSignature2021") => (),
        _ => return Err(Error::JsonLd(JsonLdError::UnexpectedTriple(type_triple.clone()))),
    };
    let proof_id = &type_triple.subject;

    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#proofPurpose",
        proof.proof_purpose.as_ref().map(|pp| pp.to_iri()),
    )?;
    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#verificationMethod",
        proof.verification_method.as_deref(),
    )?;
    graph_ref.match_iri_or_string_property(
        proof_id,
        "https://w3id.org/security#challenge",
        proof.challenge.as_deref(),
    )?;
    graph_ref.match_iri_or_string_property(
        proof_id,
        "https://w3id.org/security#domain",
        proof.domain.as_deref(),
    )?;
    graph_ref.match_date_property(
        proof_id,
        "http://purl.org/dc/terms/created",
        proof.created.as_ref(),
    )?;
    graph_ref.match_json_property(
        proof_id,
        "https://w3id.org/security#publicKeyJwk",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyJwk")),
    )?;
    graph_ref.match_multibase_property(
        proof_id,
        "https://w3id.org/security#publicKeyMultibase",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyMultibase")),
    )?;
    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#capability",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capability"))
            .and_then(|cap| cap.as_str()),
    )?;
    graph_ref.match_list_property(
        proof_id,
        "https://w3id.org/security#capabilityChain",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capabilityChain")),
    )?;

    // Disallow additional unexpected statements
    if let Some(triple) = graph_ref.triples.into_iter().next() {
        return Err(Error::JsonLd(JsonLdError::UnexpectedTriple(triple.clone())));
    }

    Ok(())
}
