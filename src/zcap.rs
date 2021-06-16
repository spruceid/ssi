use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::did_resolve::{DIDResolver, ResolutionInputMetadata};
use crate::error::Error;
use crate::jsonld::{json_to_dataset, StaticLoader};
use crate::jwk::{JWTKeys, JWK};
use crate::ldp::{now_ms, LinkedDataDocument, LinkedDataProofs, ProofPreparation};
use crate::one_or_many::OneOrMany;
use crate::rdf::DataSet;
use crate::vc::{Check, LinkedDataProofOptions, Proof, ProofPurpose, VerificationResult, URI};

use async_trait::async_trait;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_CONTEXT: &str = "https://w3id.org/security/v2";

// limited initial definition of a ZCAP Delegation, generic over Action and Caveat types
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Delegation<A, C> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    pub parent_capability: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoker: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_action: Option<A>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<C>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
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
        match &self.proof {
            None => VerificationResult::error("No applicable proof"),
            Some(proof) => {
                let mut result = proof.verify(self, resolver).await;
                if result.errors.is_empty() {
                    result.checks.push(Check::Proof);
                }
                result
            }
        }
    }

    // https://w3c-ccg.github.io/ld-proofs/
    pub async fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, jwk).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<ProofPreparation, Error> {
        LinkedDataProofs::prepare(self, options, public_key).await
    }

    pub fn set_proof(self, proof: Proof) -> Self {
        Self {
            proof: Some(proof),
            ..self
        }
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

// limited initial definition of a ZCAP Invocation, generic over Action
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Invocation<A> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_action: Option<A>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl<A> Invocation<A>
where
    A: Serialize + Send + Sync + Clone,
{
    pub async fn verify<C>(
        &self,
        _options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<A, C>,
    ) -> VerificationResult
    where
        C: Serialize + Send + Sync + Clone,
    {
        match &self.proof {
            None => VerificationResult::error("No applicable proof"),
            Some(proof) => {
                let mut result = proof.verify(self, resolver).await;
                match (
                    // get cap id from proof extra properties
                    proof
                        .property_set
                        .as_ref()
                        .and_then(|ps| ps.get("capability").map(|s| s.clone()))
                        .and_then(|v| match v {
                            Value::String(id) => Some(id),
                            _ => None,
                        }),
                    &target_capability.id,
                ) {
                    (Some(ref id), URI::String(ref t_id)) => {
                        // ensure proof target cap ID and given
                        if id != t_id {
                            result
                                .errors
                                .push("Target Capability IDs doesnt match".into())
                        };
                    }
                    _ => result
                        .errors
                        .push("Missing proof target capability ID".into()),
                };
                // if there are invokers listed in the target, ensure the inoker here is the right one
                if let (Some(URI::String(ref invoker)), Some(ref delegatee)) =
                    (&target_capability.invoker, &proof.verification_method)
                {
                    if invoker == delegatee {
                        result.errors.push("Incorrect Invoker".into());
                    }
                };
                if result.errors.is_empty() {
                    result.checks.push(Check::Proof);
                };
                result
            }
        }
    }

    // https://w3c-ccg.github.io/ld-proofs/
    pub async fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
        target: &URI,
    ) -> Result<Proof, Error> {
        let mut proof = LinkedDataProofs::sign(self, options, jwk).await?;
        proof.property_set = match (proof.property_set, target) {
            (Some(mut ps), URI::String(t)) => {
                ps.insert("capability".into(), Value::String(t.to_string()));
                Some(ps)
            }
            (_, URI::String(t)) => {
                let mut ps = Map::<String, Value>::new();
                ps.insert("capability".into(), Value::String(t.to_string()));
                Some(ps)
            }
        };
        Ok(proof)
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        target: &URI,
    ) -> Result<ProofPreparation, Error> {
        let mut prep = LinkedDataProofs::prepare(self, options, public_key).await?;
        prep.proof.property_set = match (prep.proof.property_set, target) {
            (Some(mut ps), URI::String(t)) => {
                ps.insert("capability".into(), Value::String(t.to_string()));
                Some(ps)
            }
            (_, URI::String(t)) => {
                let mut ps = Map::<String, Value>::new();
                ps.insert("capability".into(), Value::String(t.to_string()));
                Some(ps)
            }
        };
        Ok(prep)
    }

    pub fn set_proof(self, proof: Proof) -> Self {
        Self {
            proof: Some(proof),
            ..self
        }
    }
}

#[async_trait]
impl<A> LinkedDataDocument for Invocation<A>
where
    A: Serialize + Send + Sync + Clone,
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

impl Default for Contexts {
    fn default() -> Self {
        Self::One(Context::URI(URI::String(DEFAULT_CONTEXT.into())))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::example::DIDExample;

    #[derive(Deserialize, PartialEq, Debug, Clone, Serialize)]
    enum Actions {
        Read,
        Write,
    }
    impl Default for Actions {
        fn default() -> Self {
            Self::Read
        }
    }
    #[test]
    fn delegation_from_json() {
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

    #[test]
    fn invocation_from_json() {
        #[derive(Deserialize, PartialEq, Debug, Clone, Serialize)]
        enum AC {
            Drive,
        }
        let zcap_str = include_str!("../examples/zcap_invocation.jsonld");
        let zcap: Invocation<AC> = serde_json::from_str(zcap_str).unwrap();
        assert_eq!(
            zcap.context,
            Contexts::One(Context::URI(URI::String(DEFAULT_CONTEXT.into())))
        );
        assert_eq!(
            zcap.id,
            URI::String("urn:uuid:ad86cb2c-e9db-434a-beae-71b82120a8a4".into())
        );
        assert_eq!(zcap.capability_action, Some(AC::Drive));
    }

    #[async_std::test]
    async fn round_trip() {
        use crate::did::{DIDMethod, Source};
        use crate::did_resolve::DIDResolver;

        let dk = DIDExample;

        let alice_did = "did:example:foo";
        let alice: JWK = JWK {
            key_id: Some(format!("{}#key2", alice_did)),
            ..serde_json::from_str(include_str!("../tests/ed25519-2020-10-18.json")).unwrap()
        };

        let bob_did = "did:example:bar";
        let bob: JWK = JWK {
            key_id: Some(format!("{}#key1", bob_did)),
            ..serde_json::from_str(include_str!("../tests/ed25519-2021-06-16.json")).unwrap()
        };

        let del: Delegation<Actions, ()> = Delegation {
            id: URI::String("a_uri".into()),
            parent_capability: URI::String("kepler://alices_orbit".into()),
            invoker: Some(URI::String(bob_did.into())),
            capability_action: Some(Actions::Read),
            ..Default::default()
        };
        let inv: Invocation<Actions> = Invocation {
            id: URI::String("a_different_uri".into()),
            capability_action: Some(Actions::Read),
            ..Default::default()
        };

        let signed_del = del.clone().set_proof(
            del.generate_proof(
                &alice,
                &LinkedDataProofOptions {
                    verification_method: alice.key_id.clone(),
                    proof_purpose: Some(ProofPurpose::CapabilityDelegation),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        let signed_inv = inv.clone().set_proof(
            inv.generate_proof(
                &bob,
                &LinkedDataProofOptions {
                    verification_method: bob.key_id.clone(),
                    proof_purpose: Some(ProofPurpose::CapabilityInvocation),
                    ..Default::default()
                },
                &del.id,
            )
            .await
            .unwrap(),
        );

        assert!(signed_del.verify(None, &dk).await.errors.is_empty());
        assert!(signed_inv
            .verify(None, &dk, &signed_del)
            .await
            .errors
            .is_empty());
    }
}
