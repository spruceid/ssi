//! [ZCAP-LD][zcap-ld] implementation for SSI.
//!
//! [zcap-ld]: <https://w3c-ccg.github.io/zcap-spec/>
pub mod error;
use std::{
    borrow::Cow,
    collections::HashMap,
    hash::Hash,
    ops::{Deref, DerefMut},
};

pub use error::Error;

use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::{data_integrity::AnyProof, ProofValidity, Verifiable};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, WithJsonLdContext};

use ssi_claims::{
    data_integrity::{
        signing, verification::method::Signer, AnyInputContext, AnySignatureProtocol, AnySuite,
        AnySuiteOptions, CryptographicSuite, CryptographicSuiteInput, Proof, ProofConfiguration,
        ProofConfigurationExpansion, ProofConfigurationRefExpansion, ProofPreparationError,
    },
    vc::{Context, RequiredContext},
    ExtractProof, MergeWithProof, Validate, VerifiableClaims,
};
use ssi_verification_methods::{
    AnyMethod, ProofPurpose, VerificationError, VerificationMethodResolver,
};
use static_iref::iri;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityV2;

impl RequiredContext for SecurityV2 {
    const CONTEXT_IRI: &'static iref::Iri = iri!("https://w3id.org/security/v2");
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DefaultProps<A> {
    /// Capability action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_action: Option<A>,

    /// Additional properties.
    #[serde(flatten)]
    pub extra_fields: HashMap<String, Value>,
}

impl<A> DefaultProps<A> {
    pub fn new(capability_action: Option<A>) -> Self {
        Self {
            capability_action,
            extra_fields: HashMap::new(),
        }
    }
}

/// ZCAP Delegation, generic over Caveat and
/// additional properties
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delegation<C, P = DefaultProps<String>> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<SecurityV2>,

    /// Identifier.
    pub id: UriBuf,

    /// Parent capability.
    pub parent_capability: UriBuf,

    /// Invoker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoker: Option<UriBuf>,

    /// Caveat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<C>,

    /// Additional properties.
    #[serde(flatten)]
    pub additional_properties: P,
}

impl<C, P> Delegation<C, P> {
    /// Creates a new delegation.
    pub fn new(id: UriBuf, parent_capability: UriBuf, additional_properties: P) -> Self {
        Self {
            context: Context::default(),
            id,
            parent_capability,
            invoker: None,
            caveat: None,
            additional_properties,
        }
    }

    pub fn validate_invocation<S>(
        &self,
        invocation: &Verifiable<Invocation<S>, AnyProof>,
    ) -> Result<(), InvocationValidationError> {
        let id: &Uri = invocation
            .proof()
            .extra_properties
            .get("capability")
            .and_then(json_syntax::Value::as_str)
            .ok_or(InvocationValidationError::MissingTargetId)?
            .try_into()
            .map_err(|_| InvocationValidationError::IdMismatch)?;

        if id != &self.id {
            return Err(InvocationValidationError::IdMismatch);
        };

        if let Some(invoker) = &self.invoker {
            if invoker.as_iri() != invocation.proof().configuration().verification_method.id() {
                return Err(InvocationValidationError::IncorrectInvoker);
            }
        }

        Ok(())
    }

    /// Sign the delegation.
    pub async fn sign(
        self,
        suite: AnySuite,
        resolver: &impl VerificationMethodResolver<AnyMethod>,
        signer: &impl Signer<AnyMethod, ssi_jwk::Algorithm, AnySignatureProtocol>,
        proof_configuration: ProofConfiguration<AnyMethod, AnySuiteOptions>,
        capability_chain: &[&str],
    ) -> Result<Verifiable<Self, AnyProof>, signing::Error>
    where
        C: Serialize,
        P: Serialize,
    {
        self.sign_with(
            suite,
            AnyInputContext::default(),
            resolver,
            signer,
            proof_configuration,
            capability_chain,
        )
        .await
    }

    /// Sign the delegation with a custom cryptographic suite and environment.
    pub async fn sign_with<S: CryptographicSuite, E>(
        self,
        suite: S,
        environment: E,
        resolver: &impl VerificationMethodResolver<S::VerificationMethod>,
        signer: &impl Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
        mut proof_configuration: ProofConfiguration<S::VerificationMethod, S::Options>,
        capability_chain: &[&str],
    ) -> Result<Verifiable<Self, Proof<S>>, signing::Error<E::LoadError>>
    where
        S: CryptographicSuiteInput<Self, E>,
        E: ProofConfigurationExpansion + for<'a> ProofConfigurationRefExpansion<'a, S>,
    {
        proof_configuration.extra_properties.insert(
            "capabilityChain".into(),
            json_syntax::to_value(capability_chain).unwrap(),
        );

        if proof_configuration.proof_purpose != ProofPurpose::CapabilityDelegation {
            // TODO invalid proof purpose.
        }

        suite
            .sign_single(self, environment, resolver, signer, proof_configuration)
            .await
    }
}

impl<C, P> WithJsonLdContext for Delegation<C, P> {
    fn json_ld_context(&self) -> Cow<json_ld::syntax::Context> {
        Cow::Borrowed(self.context.as_ref())
    }
}

impl<C, P> Validate for Delegation<C, P> {
    fn is_valid(&self) -> bool {
        true
    }
}

impl<C, P, E, V, L> ssi_rdf::Expandable<E> for Delegation<C, P>
where
    C: Serialize,
    P: Serialize,
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send + std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    // type Resource = I::Resource;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json).expand(environment).await
    }
}

/// Verifiable ZCAP Delegation, generic over Caveat and
/// additional properties.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableDelegation<C, P = DefaultProps<String>> {
    /// Delegation.
    #[serde(flatten)]
    delegation: Delegation<C, P>,

    /// Data-Integrity Proof.
    pub proof: AnyProof,
}

impl<C, P> VerifiableDelegation<C, P> {
    pub fn new(delegation: Delegation<C, P>, proof: AnyProof) -> Self {
        Self { delegation, proof }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationVerificationError {
    #[error("invalid proof purpose")]
    InvalidProofPurpose,

    #[error(transparent)]
    ProofPreparation(#[from] ProofPreparationError),

    #[error(transparent)]
    Verification(#[from] VerificationError),
}

impl<C, P> VerifiableDelegation<C, P> {
    pub async fn into_verifiable_claims(
        self,
    ) -> Result<Verifiable<Delegation<C, P>, AnyProof>, DelegationVerificationError>
    where
        C: Serialize,
        P: Serialize,
    {
        if self.proof.configuration().proof_purpose != ProofPurpose::CapabilityDelegation {
            return Err(DelegationVerificationError::InvalidProofPurpose);
        }

        Verifiable::new(self).await.map_err(Into::into)
    }

    pub async fn verify(
        &self,
        resolver: &impl VerificationMethodResolver<AnyMethod>,
    ) -> Result<ProofValidity, DelegationVerificationError>
    where
        C: Clone + Serialize,
        P: Clone + Serialize,
    {
        let vc = self.clone().into_verifiable_claims().await?;
        vc.verify(resolver).await.map_err(Into::into)
    }
}

impl<C, P> Deref for VerifiableDelegation<C, P> {
    type Target = Delegation<C, P>;

    fn deref(&self) -> &Self::Target {
        &self.delegation
    }
}

impl<C, P> VerifiableClaims for VerifiableDelegation<C, P> {
    type Proof = AnyProof;

    fn proof(&self) -> &Self::Proof {
        &self.proof
    }
}

impl<C, P> ExtractProof for VerifiableDelegation<C, P> {
    type Proofless = Delegation<C, P>;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof) {
        (self.delegation, self.proof)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationValidationError {
    #[error("Target Capability IDs don't match")]
    IdMismatch,

    #[error("Missing proof target capability ID")]
    MissingTargetId,

    #[error("Incorrect Invoker")]
    IncorrectInvoker,
}

// limited initial definition of a ZCAP Invocation, generic over Action
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Invocation<P = DefaultProps<String>> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<SecurityV2>,

    /// Identifier.
    pub id: UriBuf,

    /// Extra properties.
    #[serde(flatten)]
    pub property_set: P,
}

impl<P> Invocation<P> {
    pub fn new(id: UriBuf, property_set: P) -> Self {
        Self {
            context: Context::default(),
            id,
            property_set,
        }
    }

    /// Sign the delegation.
    pub async fn sign(
        self,
        suite: AnySuite,
        resolver: &impl VerificationMethodResolver<AnyMethod>,
        signer: &impl Signer<AnyMethod, ssi_jwk::Algorithm, AnySignatureProtocol>,
        mut proof_configuration: ProofConfiguration<AnyMethod, AnySuiteOptions>,
        target: &Uri,
    ) -> Result<VerifiableInvocation<P>, signing::Error>
    where
        P: Serialize,
    {
        proof_configuration
            .extra_properties
            .insert("capability".into(), json_syntax::to_value(target).unwrap());

        Ok(Verifiable::unprepare(
            suite
                .sign_single(
                    self,
                    AnyInputContext::default(),
                    resolver,
                    signer,
                    proof_configuration,
                )
                .await?,
        ))
    }
}

impl<P> WithJsonLdContext for Invocation<P> {
    fn json_ld_context(&self) -> Cow<json_ld::syntax::Context> {
        Cow::Borrowed(self.context.as_ref())
    }
}

impl<P> MergeWithProof<AnyProof> for Invocation<P> {
    type WithProofs = VerifiableInvocation<P>;

    fn merge_with_proof(self, proof: AnyProof) -> Self::WithProofs {
        VerifiableInvocation {
            invocation: self,
            proof,
        }
    }
}

impl<P, E, V, L> ssi_rdf::Expandable<E> for Invocation<P>
where
    P: Serialize,
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send + std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    // type Resource = I::Resource;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json).expand(environment).await
    }
}

impl<P> Validate for Invocation<P> {
    fn is_valid(&self) -> bool {
        true
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableInvocation<P> {
    #[serde(flatten)]
    invocation: Invocation<P>,

    pub proof: AnyProof,
}

impl<P> VerifiableInvocation<P> {
    pub fn new(invocation: Invocation<P>, proof: AnyProof) -> Self {
        Self { invocation, proof }
    }
}

impl<P> VerifiableInvocation<P> {
    pub async fn into_verifiable_claims<C, Q>(
        self,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<C, Q>,
    ) -> Result<Verifiable<Invocation<P>, AnyProof>, InvocationVerificationError>
    where
        P: Serialize,
    {
        if self.proof.configuration().proof_purpose != ProofPurpose::CapabilityInvocation {
            return Err(InvocationVerificationError::InvalidProofPurpose);
        }

        let vc = Verifiable::new(self).await?;
        target_capability.validate_invocation(&vc)?;
        Ok(vc)
    }

    pub async fn verify<C, Q>(
        &self,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<C, Q>,
        verifier: &impl VerificationMethodResolver<AnyMethod>,
    ) -> Result<ProofValidity, InvocationVerificationError>
    where
        P: Clone + Serialize,
    {
        let vc = self
            .clone()
            .into_verifiable_claims(target_capability)
            .await?;
        vc.verify(verifier).await.map_err(Into::into)
    }
}

impl<P> Deref for VerifiableInvocation<P> {
    type Target = Invocation<P>;

    fn deref(&self) -> &Self::Target {
        &self.invocation
    }
}

impl<P> DerefMut for VerifiableInvocation<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.invocation
    }
}

impl<P> VerifiableClaims for VerifiableInvocation<P> {
    type Proof = AnyProof;

    fn proof(&self) -> &Self::Proof {
        &self.proof
    }
}

impl<P> ExtractProof for VerifiableInvocation<P> {
    type Proofless = Invocation<P>;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof) {
        (self.invocation, self.proof)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationVerificationError {
    #[error("validation failed: {0}")]
    ValidationFailed(#[from] InvocationValidationError),

    #[error("invalid proof purpose")]
    InvalidProofPurpose,

    #[error(transparent)]
    ProofPreparation(#[from] ProofPreparationError),

    #[error(transparent)]
    Verification(#[from] VerificationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_claims::UnprepareProof;
    use ssi_dids_core::{example::ExampleDIDResolver, DIDVerifier};
    use ssi_jwk::JWK;
    use ssi_verification_methods::signer::SingleSecretSigner;
    use static_iref::uri;

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
        let zcap_str = include_str!("../../../examples/files/zcap_delegation.jsonld");
        let zcap: Delegation<(), ()> = serde_json::from_str(zcap_str).unwrap();
        assert_eq!(
            zcap.id,
            uri!("https://whatacar.example/a-fancy-car/proc/7a397d7b")
        );
        assert_eq!(
            zcap.parent_capability,
            uri!("https://whatacar.example/a-fancy-car")
        );
        assert_eq!(
            zcap.invoker.as_deref(),
            Some(uri!("https://social.example/alyssa#key-for-car"))
        );
    }

    #[test]
    fn invocation_from_json() {
        #[derive(Deserialize, PartialEq, Debug, Clone, Serialize)]
        enum AC {
            Drive,
        }
        let zcap_str = include_str!("../../../examples/files/zcap_invocation.jsonld");
        let zcap: Invocation<DefaultProps<AC>> = serde_json::from_str(zcap_str).unwrap();
        assert_eq!(
            zcap.id,
            uri!("urn:uuid:ad86cb2c-e9db-434a-beae-71b82120a8a4")
        );
        assert_eq!(zcap.property_set.capability_action, Some(AC::Drive));
    }

    #[async_std::test]
    async fn round_trip() {
        let dk = DIDVerifier::new(ExampleDIDResolver::new());

        let alice_did = "did:example:foo";
        let alice_vm = UriBuf::new(format!("{}#key2", alice_did).into_bytes()).unwrap();
        let alice = SingleSecretSigner::new(JWK {
            key_id: Some(alice_vm.clone().into()),
            ..serde_json::from_str(include_str!("../../../tests/ed25519-2020-10-18.json")).unwrap()
        });

        let bob_did = "did:example:bar";
        let bob_vm = UriBuf::new(format!("{}#key1", bob_did).into_bytes()).unwrap();
        let bob = SingleSecretSigner::new(JWK {
            key_id: Some(bob_vm.clone().into()),
            ..serde_json::from_str(include_str!("../../../tests/ed25519-2021-06-16.json")).unwrap()
        });

        let del: Delegation<(), DefaultProps<Actions>> = Delegation {
            invoker: Some(bob_vm.clone()),
            ..Delegation::new(
                uri!("urn:a_urn").to_owned(),
                uri!("kepler://alices_orbit").to_owned(),
                DefaultProps::new(Some(Actions::Read)),
            )
        };
        let inv: Invocation<DefaultProps<Actions>> = Invocation::new(
            uri!("urn:a_different_urn").to_owned(),
            DefaultProps::new(Some(Actions::Read)),
        );

        let ldpo_alice = ProofConfiguration::new(
            "2024-02-13T16:25:26Z".parse().unwrap(),
            alice_vm.clone().into_iri().into(),
            ProofPurpose::CapabilityDelegation,
            Default::default(),
        );
        let ldpo_bob = ProofConfiguration::new(
            "2024-02-13T16:25:26Z".parse().unwrap(),
            bob_vm.clone().into_iri().into(),
            ProofPurpose::CapabilityInvocation,
            Default::default(),
        );

        let signed_del = del
            .clone()
            .sign(
                AnySuite::pick(alice.secret(), Some(&ldpo_alice.verification_method)).unwrap(),
                &dk,
                &alice,
                ldpo_alice.clone(),
                &[],
            )
            .await
            .unwrap();

        let signed_inv = inv
            .sign(
                AnySuite::pick(bob.secret(), Some(&ldpo_bob.verification_method)).unwrap(),
                &dk,
                &bob,
                ldpo_bob,
                &signed_del.claims().id,
            )
            .await
            .unwrap();

        // happy path
        assert!(signed_del.verify(&dk).await.unwrap().is_valid());

        assert!(signed_inv
            .verify(signed_del.claims(), &dk)
            .await
            .unwrap()
            .is_valid());

        let bad_sig_del = VerifiableDelegation::new(
            Delegation {
                invoker: Some(uri!("did:someone_else").to_owned()),
                ..signed_del.claims().clone()
            },
            signed_del.proof().clone().unprepare(),
        );
        let mut bad_sig_inv = signed_inv.clone();
        bad_sig_inv.id = uri!("urn:different_id").to_owned();

        // invalid proof for data
        assert!(bad_sig_del.verify(&dk).await.unwrap().is_invalid());
        assert!(bad_sig_inv
            .verify(signed_del.claims(), &dk)
            .await
            .unwrap()
            .is_invalid());

        // invalid cap attrs, invoker not matching
        let wrong_del = Delegation {
            invoker: Some(uri!("did:example:someone_else").to_owned()),
            ..del.clone()
        };
        let signed_wrong_del = wrong_del
            .sign(
                AnySuite::pick(alice.secret(), Some(&ldpo_alice.verification_method)).unwrap(),
                &dk,
                &alice,
                ldpo_alice,
                &[],
            )
            .await
            .unwrap();
        assert!(signed_inv
            .verify(signed_wrong_del.claims(), &dk)
            .await
            .is_err());
    }
}
