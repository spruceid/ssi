use std::collections::HashMap as Map;
use std::{convert::TryFrom, str::FromStr};

use chrono::prelude::*;

use crate::dataintegrity::DataIntegrityCryptoSuite;

use super::*;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_dids::VerificationRelationship as ProofPurpose;
use ssi_json_ld::{json_to_dataset, parse_ld_context, ContextLoader};

const RDF_TYPE: Iri<'static> = iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
const RDF_NIL: Iri<'static> = iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#nil");
const RDF_FIRST: Iri<'static> = iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#first");
const RDF_REST: Iri<'static> = iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest");

#[macro_export]
macro_rules! assert_local {
    ($cond:expr) => {
        if !$cond {
            return false;
        }
    };
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
// TODO use enum to separate betwen JWS and LD proofs?
// TODO create generics type to allow users to provide their own proof suite that implements ProofSuite
pub struct Proof {
    #[serde(rename = "@context")]
    // TODO: use consistent types for context
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
    #[serde(rename = "type")]
    pub type_: ProofSuiteType,
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
    pub cryptosuite: Option<dataintegrity::DataIntegrityCryptoSuite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl Proof {
    pub fn new(type_: ProofSuiteType) -> Self {
        Self {
            type_,
            context: Value::default(),
            proof_purpose: None,
            proof_value: None,
            challenge: None,
            creator: None,
            verification_method: None,
            created: None,
            domain: None,
            nonce: None,
            jws: None,
            property_set: None,
            cryptosuite: None,
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
            created: Some(options.created.unwrap_or_else(now_ns)),
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
            assert_local!(options.created.unwrap_or_else(now_ns) >= created);
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
        nonce: Option<&String>,
        disclosed_message_indices: Option<&Vec<usize>>,
    ) -> VerificationResult {
        LinkedDataProofs::verify(
            self,
            document,
            resolver,
            context_loader,
            nonce,
            disclosed_message_indices,
        )
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
        let json = json_syntax::to_value_with(copy, Default::default).unwrap();
        let dataset = json_to_dataset(
            json,
            context_loader,
            parent
                .map(LinkedDataDocument::get_contexts)
                .transpose()?
                .flatten()
                .as_deref()
                .map(parse_ld_context)
                .transpose()?,
        )
        .await?;

        verify_proof_consistency(self, &dataset)?;
        Ok(dataset)
    }

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(self)?)
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
    pub type_: Option<ProofSuiteType>,
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
    /// The nonce of the proof.
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Indices of disclosed messages
    pub disclosed_message_indices: Option<Vec<usize>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<DataIntegrityCryptoSuite>,
}

impl Default for LinkedDataProofOptions {
    fn default() -> Self {
        Self {
            verification_method: None,
            proof_purpose: Some(ProofPurpose::default()),
            created: Some(crate::now_ns()),
            challenge: None,
            domain: None,
            checks: Some(vec![Check::Proof]),
            eip712_domain: None,
            type_: None,
            cryptosuite: None,
            nonce: None,
            disclosed_message_indices: None,
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

#[derive(thiserror::Error, Debug)]
pub enum ProofInconsistency {
    /// RDF statement object does not match value.
    #[error(
        "RDF statement object does not match value. Predicate: {0}. Expected: {1}. Actual: {2}"
    )]
    ObjectMismatch(IriBuf, String, String),

    /// Missing RDF statement object.
    #[error("Missing RDF statement object. Predicate: {0}. Expected value: {1}")]
    ExpectedObject(IriBuf, String),

    /// Unexpected RDF statement object.
    #[error("Unexpected RDF statement object. Predicate: {0}. Value: {1}")]
    UnexpectedObject(IriBuf, String),

    /// List item mismatch.
    #[error("List item mismatch. Value in RDF: {0}. Value in JSON: {1}")]
    ListItemMismatch(String, String),

    /// Invalid RDF list.
    #[error("Invalid list")]
    InvalidList,

    /// Unexpected end of list.
    #[error("Unexpected end of list")]
    UnexpectedEndOfList,

    /// Expected end of list.
    #[error("Expected end of list")]
    ExpectedEndOfList,

    /// Missing RDF type.
    #[error("Missing type")]
    MissingType,

    /// Invalid RDF type value.
    #[error("Invalid type value")]
    InvalidType,

    /// Missing associated context.
    #[error("Missing associated context: {0}")]
    MissingAssociatedContext(IriBuf),

    /// Unexpected RDF triple.
    #[error("Unexpected triple {0:?}")]
    UnexpectedTriple(Box<rdf_types::Triple>),
}

/// Verify alignment of proof options in JSON with RDF terms
fn verify_proof_consistency(
    proof: &Proof,
    dataset: &DataSet,
) -> Result<(), Box<ProofInconsistency>> {
    let mut dataset = dataset.clone();
    let graph_ref = dataset.default_graph_mut();

    let type_triple = graph_ref
        .take_match::<rdf_types::Subject, _, rdf_types::Object>(rdf_types::Triple(
            None,
            Some(&RDF_TYPE),
            None,
        ))
        .ok_or(ProofInconsistency::MissingType)?;

    let type_iri = type_triple
        .object()
        .as_iri()
        .ok_or(ProofInconsistency::InvalidType)?;

    if !proof
        .type_
        .associated_contexts()
        .contains(&type_iri.as_str())
    {
        return Err(Box::new(ProofInconsistency::MissingAssociatedContext(
            type_iri.clone(),
        )));
    }

    let proof_id = type_triple.subject();

    graph_ref.take_object_and_assert_eq_iri(
        proof_id,
        iri!("https://w3id.org/security#proofPurpose"),
        proof.proof_purpose.as_ref().map(|pp| pp.to_iri()),
    )?;

    // FIXME: this only works under the (false) assumption that
    // `verificationMethod` is always an IRI.
    // See: https://www.w3.org/TR/did-core/#did-document-properties
    graph_ref.take_object_and_assert_eq_iri(
        proof_id,
        iri!("https://w3id.org/security#verificationMethod"),
        proof
            .verification_method
            .as_ref()
            .map(|m| Iri::new(m).unwrap()),
    )?;

    graph_ref.take_object_and_assert_eq_iri_or_str(
        proof_id,
        iri!("https://w3id.org/security#challenge"),
        proof.challenge.as_deref(),
    )?;

    graph_ref.take_object_and_assert_eq_iri_or_str(
        proof_id,
        iri!("https://w3id.org/security#domain"),
        proof.domain.as_deref(),
    )?;

    graph_ref.take_object_and_assert_eq_date(
        proof_id,
        iri!("http://purl.org/dc/terms/created"),
        proof.created.as_ref(),
    )?;

    graph_ref.take_object_and_assert_eq_json(
        proof_id,
        iri!("https://w3id.org/security#publicKeyJwk"),
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyJwk")),
    )?;

    graph_ref.take_object_and_assert_eq_multibase(
        proof_id,
        iri!("https://w3id.org/security#publicKeyMultibase"),
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyMultibase"))
            .and_then(|cap| cap.as_str()),
    )?;

    graph_ref.take_object_and_assert_eq_iri_or_str(
        proof_id,
        iri!("https://w3id.org/security#cryptosuite"),
        proof
            .cryptosuite
            .clone()
            .map(|cc| cc.to_string())
            .as_deref(),
    )?;

    graph_ref.take_object_and_assert_eq_iri(
        proof_id,
        iri!("https://w3id.org/security#capability"),
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capability"))
            .and_then(|cap| cap.as_str())
            .map(|cap| Iri::new(cap).unwrap()),
    )?;

    graph_ref.take_object_and_assert_eq_list(
        proof_id,
        iri!("https://w3id.org/security#capabilityChain"),
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capabilityChain"))
            .map(|cc| cc.as_array().unwrap().iter()),
        |item, expected| match expected.as_str() {
            Some(e) => match (item, Iri::new(e)) {
                (rdf_types::Term::Iri(iri), Ok(expected)) => *iri == expected,
                _ => false,
            },
            None => false,
        },
    )?;

    // Disallow additional unexpected statements
    if let Some(rdf_types::Triple(s, p, o)) = graph_ref.triples().next() {
        return Err(Box::new(ProofInconsistency::UnexpectedTriple(Box::new(
            rdf_types::Triple(s.clone(), p.clone(), o.clone()),
        ))));
    }

    Ok(())
}

/// RDF graph extension adding utility methods on proof graphs.
trait ProofGraph:
    grdf::Graph<Subject = rdf_types::Subject, Predicate = IriBuf, Object = rdf_types::Object>
    + for<'a> grdf::GraphTake<rdf_types::Subject, Iri<'a>, rdf_types::Object>
{
    /// Take any statement of the form `s p o` for the given `s` and `p`
    /// and call `object_predicate(Some(o))`.
    /// If no statement has the form `s p o`, call `object_predicate(None)`.
    fn take_object_and_assert<E>(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        object_predicate: impl FnOnce(&mut Self, Option<Self::Object>) -> Result<(), E>,
    ) -> Result<(), E> {
        match self.take_match(rdf_types::Triple(Some(s), Some(&p), None)) {
            Some(rdf_types::Triple(_, _, o)) => object_predicate(self, Some(o)),
            None => object_predicate(self, None),
        }
    }

    /// When `expected_o` is `Some(iri)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to `iri` according to `eq`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq<V: ToString>(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<V>,
        eq: impl FnOnce(&Self::Object, &V) -> bool,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert(s, p, |_, o| match (o, expected_o) {
            (Some(o), Some(expected)) => {
                if eq(&o, &expected) {
                    Ok(())
                } else {
                    Err(Box::new(ProofInconsistency::ObjectMismatch(
                        p.to_owned(),
                        expected.to_string(),
                        o.to_string(),
                    )))
                }
            }
            (None, None) => Ok(()),
            (None, Some(expected_iri)) => Err(Box::new(ProofInconsistency::ExpectedObject(
                p.to_owned(),
                expected_iri.to_string(),
            ))),
            (Some(o), None) => Err(Box::new(ProofInconsistency::UnexpectedObject(
                p.to_owned(),
                o.to_string(),
            ))),
        })
    }

    /// When `expected_o` is `Some(json)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to the JSON array value `json`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_list<I: Iterator>(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<I>,
        eq: impl Fn(&Self::Object, &I::Item) -> bool,
    ) -> Result<(), Box<ProofInconsistency>>
    where
        I::Item: ToString,
    {
        fn format_list<I: Iterator>(list: I) -> String
        where
            I::Item: ToString,
        {
            let mut expected_string = "[".to_string();

            for (i, item) in list.enumerate() {
                if i > 0 {
                    expected_string.push(',');
                }

                expected_string.push_str(&item.to_string());
            }

            expected_string.push(']');
            expected_string
        }

        self.take_object_and_assert(s, p, |this, o| match (o, expected_o) {
            (Some(o), Some(expected)) => {
                let mut head = match o {
                    rdf_types::Term::Iri(i) if i == RDF_NIL => None,
                    rdf_types::Term::Iri(i) => Some(rdf_types::Subject::Iri(i)),
                    rdf_types::Term::Blank(b) => Some(rdf_types::Subject::Blank(b)),
                    rdf_types::Term::Literal(l) => {
                        return Err(Box::new(ProofInconsistency::ObjectMismatch(
                            p.to_owned(),
                            l.to_string(),
                            format_list(expected),
                        )))
                    }
                };

                for expected_item in expected {
                    match head.take() {
                        Some(id) => {
                            match this.take_match(rdf_types::Triple(
                                Some(&id),
                                Some(&RDF_FIRST),
                                None,
                            )) {
                                Some(rdf_types::Triple(_, _, first)) => {
                                    if !eq(&first, &expected_item) {
                                        return Err(Box::new(
                                            ProofInconsistency::ListItemMismatch(
                                                first.to_string(),
                                                expected_item.to_string(),
                                            ),
                                        ));
                                    }

                                    match this.take_match(rdf_types::Triple(
                                        Some(&id),
                                        Some(&RDF_REST),
                                        None,
                                    )) {
                                        Some(rdf_types::Triple(_, _, rest)) => {
                                            head = match rest {
                                                rdf_types::Term::Iri(i) if i == RDF_NIL => None,
                                                rdf_types::Term::Iri(i) => {
                                                    Some(rdf_types::Subject::Iri(i))
                                                }
                                                rdf_types::Term::Blank(b) => {
                                                    Some(rdf_types::Subject::Blank(b))
                                                }
                                                rdf_types::Term::Literal(_) => {
                                                    return Err(Box::new(
                                                        ProofInconsistency::InvalidList,
                                                    ))
                                                }
                                            };
                                        }
                                        None => {
                                            return Err(Box::new(ProofInconsistency::InvalidList))
                                        }
                                    }
                                }
                                None => return Err(Box::new(ProofInconsistency::InvalidList)),
                            }
                        }
                        None => return Err(Box::new(ProofInconsistency::UnexpectedEndOfList)),
                    }
                }

                if head.is_some() {
                    return Err(Box::new(ProofInconsistency::ExpectedEndOfList));
                }

                Ok(())
            }
            (None, None) => Ok(()),
            (None, Some(expected)) => Err(Box::new(ProofInconsistency::ExpectedObject(
                p.to_owned(),
                format_list(expected),
            ))),
            (Some(o), None) => Err(Box::new(ProofInconsistency::UnexpectedObject(
                p.to_owned(),
                o.to_string(),
            ))),
        })
    }

    /// When `expected_o` is `Some(iri)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to `iri`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_iri(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<Iri>,
    ) -> Result<(), Box<ProofInconsistency>>;

    /// When `expected_o` is `Some(str)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is an IRI or string literal equal to `str`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_iri_or_str(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&str>,
    ) -> Result<(), Box<ProofInconsistency>>;

    /// When `expected_o` is `Some(date)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to `date`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_date(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&DateTime<Utc>>,
    ) -> Result<(), Box<ProofInconsistency>>;

    /// When `expected_o` is `Some(str)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to the multibase-encoded string `str`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_multibase(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&str>,
    ) -> Result<(), Box<ProofInconsistency>>;

    /// When `expected_o` is `Some(json)`.
    /// take any statement of the form `s p o` for the given `s` and `p`
    /// and checks that `o` is equal to the JSON value `json`.
    /// When `expected_o` is `None`,
    /// checks that no statement has the form `s p o`.
    fn take_object_and_assert_eq_json(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&serde_json::Value>,
    ) -> Result<(), Box<ProofInconsistency>>;
}

impl ProofGraph for grdf::HashGraph<rdf_types::Subject, IriBuf, rdf_types::Object> {
    fn take_object_and_assert_eq_iri(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<Iri>,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert_eq(s, p, expected_o, |o, expected_iri| match o {
            rdf_types::Object::Iri(iri) => iri == expected_iri,
            _ => false,
        })
    }

    fn take_object_and_assert_eq_iri_or_str(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&str>,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert_eq(s, p, expected_o, |o, expected| match o {
            rdf_types::Object::Iri(iri) => iri.as_str() == *expected,
            rdf_types::Object::Literal(rdf_types::Literal::String(s)) => s.as_str() == *expected,
            _ => false,
        })
    }

    fn take_object_and_assert_eq_date(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&DateTime<Utc>>,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert_eq(s, p, expected_o, |o, expected| match o {
            rdf_types::Object::Literal(rdf_types::Literal::TypedString(date, ty))
                if *ty == iri!("http://www.w3.org/2001/XMLSchema#dateTime") =>
            {
                match DateTime::parse_from_rfc3339(date.as_str()) {
                    Ok(date) => date == **expected,
                    _ => false,
                }
            }
            _ => false,
        })
    }

    fn take_object_and_assert_eq_multibase(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&str>,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert_eq(s, p, expected_o, |o, expected| match o {
            rdf_types::Object::Literal(rdf_types::Literal::TypedString(s, ty)) => {
                *ty == iri!("https://w3id.org/security#multibase") && s.as_str() == *expected
            }
            _ => false,
        })
    }

    fn take_object_and_assert_eq_json(
        &mut self,
        s: &Self::Subject,
        p: Iri,
        expected_o: Option<&serde_json::Value>,
    ) -> Result<(), Box<ProofInconsistency>> {
        self.take_object_and_assert_eq(s, p, expected_o, |o, expected| match o {
            rdf_types::Object::Literal(rdf_types::Literal::TypedString(json, ty))
                if *ty == iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON") =>
            {
                match serde_json::from_str::<serde_json::Value>(json) {
                    Ok(json) => json == **expected,
                    _ => false,
                }
            }
            _ => false,
        })
    }
}
