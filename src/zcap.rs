use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::did_resolve::{DIDResolver, ResolutionInputMetadata};
use crate::error::Error;
use crate::jsonld::{json_to_dataset, StaticLoader};
use crate::jwk::{JWTKeys, JWK};
use crate::ldp::{now_ms, LinkedDataDocument, LinkedDataProofs, ProofPreparation};
use crate::one_or_many::OneOrMany;
use crate::rdf::DataSet;
use crate::vc::{Check, LinkedDataProofOptions, VerificationResult, URI};

use async_trait::async_trait;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_CONTEXT: &str = "https://w3id.org/security/v2";

// limited initial definition of a ZCAP Delegation, generic over Action and Caveat types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delegation<A, C> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    pub parent_capability: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoker: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<A>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<C>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

// limited initial definition of a ZCAP Invokation, generic over Action and Caveat types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Invokation<A> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    pub parent_capability: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<A>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl<A, C> Delegation<A, C>
where
    A: Serialize + Send + Sync + Clone,
    C: Serialize + Send + Sync + Clone,
{
    pub async fn verify(
        &self,
        _options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> VerificationResult {
        let proofs: Vec<&Proof> = self.proof.iter().flatten().collect();
        if proofs.is_empty() {
            // TODO: say why, e.g. expired
            return VerificationResult::error("No applicable proof");
        }
        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof.verify(self, resolver).await;
            if result.errors.is_empty() {
                result.checks.push(Check::Proof);
                return result;
            };
            results.append(&mut result);
        }
        results
    }
}

#[async_trait]
impl<A, C> LinkedDataDocument for Delegation<A, C>
where
    A: Serialize + Send + Sync + Clone,
    C: Serialize + Send + Sync + Clone,
{
    fn get_contexts(&self) -> Result<Option<String>, Error> {
        Ok(Some(serde_json::to_string(&self.context)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.proof = None;
        let json = serde_json::to_string(&copy)?;
        let more_contexts = match parent {
            Some(parent) => parent.get_contexts()?,
            None => None,
        };
        let mut loader = StaticLoader;
        json_to_dataset(&json, more_contexts.as_ref(), false, None, &mut loader).await
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(Map<String, Value>),
}

impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = Error;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(Error::MissingContext),
            Some(Context::URI(URI::String(uri))) => uri,
            Some(Context::Object(_)) => return Err(Error::InvalidContext),
        };
        if first_uri != DEFAULT_CONTEXT {
            return Err(Error::InvalidContext);
        }
        Ok(match context {
            OneOrMany::One(context) => Contexts::One(context),
            OneOrMany::Many(contexts) => Contexts::Many(contexts),
        })
    }
}

impl From<Contexts> for OneOrMany<Context> {
    fn from(contexts: Contexts) -> OneOrMany<Context> {
        match contexts {
            Contexts::One(context) => OneOrMany::One(context),
            Contexts::Many(contexts) => OneOrMany::Many(contexts),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "@context")]
    // TODO: use consistent types for context
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "proofPurpose")]
#[serde(rename_all = "camelCase")]
pub enum ProofPurpose {
    CapabilityDelegation { capability_chain: Vec<String> },
    CapabilityInvocation { capability: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zcap_from_json() {
        let zcap_str = include_str!("../examples/zcap_delegation.jsonld");
        let zcap: Delegation<(), ()> = serde_json::from_str(zcap_str).unwrap();
        assert_eq!(
            zcap.context,
            Contexts::One(Context::URI(URI::String(DEFAULT_CONTEXT.into())))
        );
        assert_eq!(
            zcap.id,
            URI::String("https://whatacar.example/a-fancy-car/proc/7a397d7b".into())
        );
        assert_eq!(
            zcap.parent_capability,
            URI::String("https://whatacar.example/a-fancy-car".into())
        );
        assert_eq!(
            zcap.invoker,
            Some(URI::String(
                "https://social.example/alyssa#key-for-car".into()
            ))
        );
    }
}
