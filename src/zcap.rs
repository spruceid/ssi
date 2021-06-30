use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::did_resolve::{DIDResolver, ResolutionInputMetadata};
use crate::error::Error;
use crate::jsonld::{json_to_dataset, StaticLoader, SECURITY_V2_CONTEXT};
use crate::jwk::{JWTKeys, JWK};
use crate::ldp::{now_ms, LinkedDataDocument, LinkedDataProofs, ProofPreparation};
use crate::one_or_many::OneOrMany;
use crate::rdf::DataSet;
use crate::vc::{Check, LinkedDataProofOptions, Proof, ProofPurpose, VerificationResult, URI};

use async_trait::async_trait;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_CONTEXT: &str = SECURITY_V2_CONTEXT;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DefaultProps<A> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_action: Option<A>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_fields: Option<Map<String, Value>>,
}

impl<A> DefaultProps<A> {
    pub fn new(capability_action: Option<A>) -> Self {
        Self {
            capability_action,
            extra_fields: None,
        }
    }
}

// limited initial definition of a ZCAP Delegation, generic over Caveat and additional properties
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delegation<C, S = DefaultProps<String>> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    pub parent_capability: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoker: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<C>,
    #[serde(flatten)]
    pub property_set: S,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl<C, S> Delegation<C, S> {
    pub fn new(id: URI, parent_capability: URI, property_set: S) -> Self {
        Self {
            context: Contexts::default(),
            id,
            parent_capability,
            invoker: None,
            caveat: None,
            proof: None,
            property_set,
        }
    }
}

impl<C, S> Delegation<C, S>
where
    C: Serialize + Send + Sync + Clone,
    S: Serialize + Send + Sync + Clone,
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
                if proof.proof_purpose != Some(ProofPurpose::CapabilityDelegation) {
                    result.errors.push("Incorrect Proof Purpose".into());
                };
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<C, S> LinkedDataDocument for Delegation<C, S>
where
    C: Serialize + Send + Sync + Clone,
    S: Serialize + Send + Sync + Clone,
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

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
    }
}

// limited initial definition of a ZCAP Invocation, generic over Action
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Invocation<S = DefaultProps<String>> {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: URI,
    #[serde(flatten)]
    pub property_set: S,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl<S> Invocation<S> {
    pub fn new(id: URI, property_set: S) -> Self {
        Self {
            context: Contexts::default(),
            id,
            proof: None,
            property_set,
        }
    }
}

pub trait VerifyAttributes<I> {
    type Err: std::string::ToString;
    // Fn to be implemented for invocations to be verified against delegations
    // If the property set contains e.g. Actions or Caveat-related fields, they should be checked here
    fn verify_attributes(&self, invocation: &I) -> Result<(), Self::Err> {
        Ok(())
    }
}

impl<S> Invocation<S>
where
    S: Serialize + Send + Sync + Clone,
{
    pub async fn verify<C, P>(
        &self,
        _options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<C, P>,
    ) -> VerificationResult
    where
        C: Serialize + Send + Sync + Clone,
        P: Serialize + Send + Sync + Clone,
        Delegation<C, P>: VerifyAttributes<Self>,
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
                                .push("Target Capability IDs dont match".into())
                        };
                    }
                    _ => result
                        .errors
                        .push("Missing proof target capability ID".into()),
                };
                match (&target_capability.invoker, &proof.verification_method) {
                    // if there are invokers listed in the target, ensure the inoker here is the right one
                    (Some(URI::String(ref invoker)), Some(ref delegatee)) => {
                        if invoker != delegatee {
                            result.errors.push("Incorrect Invoker".into());
                        }
                    }
                    (_, None) => result
                        .errors
                        .push("Missing Proof Verification Method".into()),
                    _ => {}
                };
                if proof.proof_purpose != Some(ProofPurpose::CapabilityInvocation) {
                    result.errors.push("Incorrect Proof Purpose".into());
                };
                if let Result::Err(e) = target_capability.verify_attributes(self) {
                    result.errors.push(e.to_string());
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
        let cl = options.clone();
        let opts = LinkedDataProofOptions {
            property_set: match (cl.property_set, target) {
                (Some(mut ps), URI::String(t)) => {
                    ps.insert("capability".into(), Value::String(t.to_string()));
                    Some(ps)
                }
                (_, URI::String(t)) => {
                    let mut ps = Map::<String, Value>::new();
                    ps.insert("capability".into(), Value::String(t.to_string()));
                    Some(ps)
                }
            },
            ..cl
        };
        LinkedDataProofs::sign(self, &opts, jwk).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        target: &URI,
    ) -> Result<ProofPreparation, Error> {
        let cl = options.clone();
        let opts = LinkedDataProofOptions {
            property_set: match (cl.property_set, target) {
                (Some(mut ps), URI::String(t)) => {
                    ps.insert("capability".into(), Value::String(t.to_string()));
                    Some(ps)
                }
                (_, URI::String(t)) => {
                    let mut ps = Map::<String, Value>::new();
                    ps.insert("capability".into(), Value::String(t.to_string()));
                    Some(ps)
                }
            },
            ..cl
        };
        LinkedDataProofs::prepare(self, &opts, public_key).await
    }

    pub fn set_proof(self, proof: Proof) -> Self {
        Self {
            proof: Some(proof),
            ..self
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S> LinkedDataDocument for Invocation<S>
where
    S: Serialize + Send + Sync + Clone,
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

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
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
        let zcap: Invocation<DefaultProps<AC>> = serde_json::from_str(zcap_str).unwrap();
        assert_eq!(
            zcap.context,
            Contexts::One(Context::URI(URI::String(DEFAULT_CONTEXT.into())))
        );
        assert_eq!(
            zcap.id,
            URI::String("urn:uuid:ad86cb2c-e9db-434a-beae-71b82120a8a4".into())
        );
        assert_eq!(zcap.property_set.capability_action, Some(AC::Drive));
    }

    #[async_std::test]
    async fn round_trip() {
        use crate::did::{DIDMethod, Source};
        use crate::did_resolve::DIDResolver;
        use std::collections::HashMap as Map;

        let dk = DIDExample;

        let alice_did = "did:example:foo";
        let alice_vm = format!("{}#key2", alice_did);
        let alice: JWK = JWK {
            key_id: Some(alice_vm),
            ..serde_json::from_str(include_str!("../tests/ed25519-2020-10-18.json")).unwrap()
        };

        let bob_did = "did:example:bar";
        let bob_vm = format!("{}#key1", bob_did);
        let bob: JWK = JWK {
            key_id: Some(bob_vm.clone()),
            ..serde_json::from_str(include_str!("../tests/ed25519-2021-06-16.json")).unwrap()
        };

        let del: Delegation<(), DefaultProps<Actions>> = Delegation {
            invoker: Some(URI::String(bob_vm)),
            ..Delegation::new(
                URI::String("urn:a_urn".into()),
                URI::String("kepler://alices_orbit".into()),
                DefaultProps::new(Some(Actions::Read)),
            )
        };
        let inv: Invocation<DefaultProps<Actions>> = Invocation::new(
            URI::String("urn:a_different_urn".into()),
            DefaultProps::new(Some(Actions::Read)),
        );

        impl VerifyAttributes<Invocation<DefaultProps<Actions>>> for Delegation<(), DefaultProps<Actions>> {
            type Err = &'static str;
            fn verify_attributes(
                &self,
                invocation: &Invocation<DefaultProps<Actions>>,
            ) -> Result<(), Self::Err> {
                if self.property_set.capability_action == invocation.property_set.capability_action
                {
                    Ok(())
                } else {
                    Err("Actions do not match")
                }
            }
        }

        let ldpo_alice = LinkedDataProofOptions {
            verification_method: alice.key_id.clone(),
            proof_purpose: Some(ProofPurpose::CapabilityDelegation),
            ..Default::default()
        };
        let ldpo_bob = LinkedDataProofOptions {
            verification_method: bob.key_id.clone(),
            proof_purpose: Some(ProofPurpose::CapabilityInvocation),
            ..Default::default()
        };
        let signed_del = del
            .clone()
            .set_proof(del.generate_proof(&alice, &ldpo_alice).await.unwrap());
        let signed_inv = inv
            .clone()
            .set_proof(inv.generate_proof(&bob, &ldpo_bob, &del.id).await.unwrap());

        // happy path
        let s_d_v = signed_del.verify(None, &dk).await;
        assert!(s_d_v.errors.is_empty());
        assert!(s_d_v.checks.iter().any(|c| c == &Check::Proof));

        let s_i_v = signed_inv.verify(None, &dk, &signed_del).await;
        assert!(s_i_v.errors.is_empty());
        assert!(s_i_v.checks.iter().any(|c| c == &Check::Proof));

        let bad_sig_del = Delegation {
            invoker: Some(URI::String("did:someone_else".into())),
            ..signed_del.clone()
        };
        let bad_sig_inv = Invocation {
            id: URI::String("urn:different_id".into()),
            ..signed_inv.clone()
        };

        // invalid proof for data
        assert!(!bad_sig_del.verify(None, &dk).await.errors.is_empty());
        assert!(!bad_sig_inv
            .verify(None, &dk, &signed_del)
            .await
            .errors
            .is_empty());

        // invalid cap attrs, invoker not matching
        let wrong_del = Delegation {
            invoker: Some(URI::String("did:example:someone_else".into())),
            ..del.clone()
        };
        let proof = wrong_del.generate_proof(&alice, &ldpo_alice).await.unwrap();
        let signed_wrong_del = wrong_del.set_proof(proof);
        assert!(!signed_inv
            .verify(None, &dk, &signed_wrong_del)
            .await
            .errors
            .is_empty());

        // invalid cap attrs, actions not matching
        let wrong_inv = Invocation {
            property_set: DefaultProps::new(Some(Actions::Write)),
            ..inv.clone()
        };
        let proof = wrong_inv
            .generate_proof(&bob, &ldpo_bob, &del.id)
            .await
            .unwrap();
        let signed_wrong_inv = wrong_inv.set_proof(proof);
        assert!(!signed_wrong_inv
            .verify(None, &dk, &signed_del)
            .await
            .errors
            .is_empty());
    }
}
