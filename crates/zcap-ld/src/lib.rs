//! [ZCAP-LD][zcap-ld] implementation for SSI.
//!
//! [zcap-ld]: <https://w3c-ccg.github.io/zcap-spec/>
pub mod error;
use std::{borrow::Cow, collections::HashMap, hash::Hash};

pub use error::Error;

use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::{
    chrono::{DateTime, Utc},
    data_integrity::{
        suite::{CryptographicSuiteSigning, InputProofOptions, InputSignatureOptions},
        AnyDataIntegrity, AnyProofs, AnySignatureAlgorithm, AnySuite, CryptographicSuite,
        DataIntegrity, Proof, Proofs,
    },
    vc::syntax::{Context, RequiredContext},
    ClaimsValidity, DateTimeProvider, Eip712TypesLoaderProvider, InvalidClaims, ResolverProvider,
    SignatureEnvironment, SignatureError, ValidateClaims, VerificationParameters,
};
use ssi_json_ld::{JsonLdError, JsonLdLoaderProvider, JsonLdNodeObject, JsonLdObject, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject};
use ssi_verification_methods::{AnyMethod, ProofPurpose, VerificationMethodResolver};
use ssi_verification_methods::{MessageSigner, Signer};
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
pub struct Delegation<C, S = DefaultProps<String>> {
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
    pub additional_properties: S,
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

    pub fn validate(&self, proofs: &Proofs<AnySuite>) -> Result<(), DelegationValidationError> {
        for proof in proofs.iter() {
            if proof.configuration().proof_purpose != ProofPurpose::CapabilityDelegation {
                return Err(DelegationValidationError::InvalidProofPurpose);
            }
        }

        Ok(())
    }

    pub fn validate_invocation_proof(
        &self,
        proof: &Proof<AnySuite>,
    ) -> Result<(), InvocationValidationError> {
        let id: &Uri = proof
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
            if invoker.as_iri() != proof.configuration().verification_method.id() {
                return Err(InvocationValidationError::IncorrectInvoker);
            }
        }

        Ok(())
    }

    /// Sign the delegation.
    pub async fn sign<S>(
        self,
        suite: AnySuite,
        resolver: &impl VerificationMethodResolver<Method = AnyMethod>,
        signer: S,
        proof_configuration: InputProofOptions<AnySuite>,
        capability_chain: &[&str],
    ) -> Result<DataIntegrity<Self, AnySuite>, SignatureError>
    where
        C: Serialize,
        P: Serialize,
        S: Signer<AnyMethod>,
        S::MessageSigner: MessageSigner<AnySignatureAlgorithm>,
    {
        self.sign_with(
            suite,
            SignatureEnvironment::default(),
            resolver,
            signer,
            proof_configuration,
            capability_chain,
        )
        .await
    }

    /// Sign the delegation with a custom cryptographic suite and environment.
    pub async fn sign_with<D, E, R, S>(
        self,
        suite: D,
        environment: E,
        resolver: R,
        signer: S,
        mut proof_configuration: InputProofOptions<D>,
        capability_chain: &[&str],
    ) -> Result<DataIntegrity<Self, D>, SignatureError>
    where
        D: CryptographicSuiteSigning<Self, E, R, S>,
        InputSignatureOptions<D>: Default,
    {
        proof_configuration.extra_properties.insert(
            "capabilityChain".into(),
            json_syntax::to_value(capability_chain).unwrap(),
        );

        if proof_configuration.proof_purpose != ProofPurpose::CapabilityDelegation {
            // TODO invalid proof purpose.
        }

        suite
            .sign_with(
                environment,
                self,
                resolver,
                signer,
                proof_configuration,
                Default::default(),
            )
            .await
    }
}

pub trait TargetCapabilityProvider {
    type Caveat;
    type AdditionalProperties;

    fn target_capability(&self) -> &Delegation<Self::Caveat, Self::AdditionalProperties>;
}

impl<'a, E: TargetCapabilityProvider> TargetCapabilityProvider for &'a E {
    type Caveat = E::Caveat;
    type AdditionalProperties = E::AdditionalProperties;

    fn target_capability(&self) -> &Delegation<Self::Caveat, Self::AdditionalProperties> {
        E::target_capability(*self)
    }
}

pub struct InvocationVerifier<'a, C, S, R, L1 = ssi_json_ld::ContextLoader, L2 = ()> {
    pub resolver: R,
    pub json_ld_loader: L1,
    pub eip712_types_loader: L2,
    pub date_time: Option<DateTime<Utc>>,
    pub delegation: &'a Delegation<C, S>,
}

impl<'a, C, S, R> InvocationVerifier<'a, C, S, R> {
    pub fn from_resolver(resolver: R, delegation: &'a Delegation<C, S>) -> Self {
        Self::from_verifier(VerificationParameters::from_resolver(resolver), delegation)
    }
}

impl<'a, R, L1, L2, C, S> InvocationVerifier<'a, C, S, R, L1, L2> {
    pub fn from_verifier(
        verifier: VerificationParameters<R, L1, L2>,
        delegation: &'a Delegation<C, S>,
    ) -> Self {
        Self {
            resolver: verifier.resolver,
            json_ld_loader: verifier.json_ld_loader,
            eip712_types_loader: verifier.eip712_types_loader,
            date_time: verifier.date_time,
            delegation,
        }
    }
}

impl<'v, 'a, R, L1, L2, C, S> InvocationVerifier<'a, C, S, &'v R, &'v L1, &'v L2> {
    pub fn from_verifier_ref(
        verifier: &'v VerificationParameters<R, L1, L2>,
        delegation: &'a Delegation<C, S>,
    ) -> Self {
        Self {
            resolver: &verifier.resolver,
            json_ld_loader: &verifier.json_ld_loader,
            eip712_types_loader: &verifier.eip712_types_loader,
            date_time: verifier.date_time,
            delegation,
        }
    }
}

impl<'a, C, S, R, L1, L2> DateTimeProvider for InvocationVerifier<'a, C, S, R, L1, L2> {
    fn date_time(&self) -> DateTime<Utc> {
        self.date_time.unwrap_or_else(Utc::now)
    }
}

impl<'a, C, S, R, L1, L2> ResolverProvider for InvocationVerifier<'a, C, S, R, L1, L2> {
    type Resolver = R;

    fn resolver(&self) -> &Self::Resolver {
        &self.resolver
    }
}

impl<'a, C, S, R, L1: ssi_json_ld::Loader, L2> JsonLdLoaderProvider
    for InvocationVerifier<'a, C, S, R, L1, L2>
{
    type Loader = L1;

    fn loader(&self) -> &Self::Loader {
        &self.json_ld_loader
    }
}

impl<'a, C, S, R, L1, L2: ssi_eip712::TypesLoader> Eip712TypesLoaderProvider
    for InvocationVerifier<'a, C, S, R, L1, L2>
{
    type Loader = L2;

    fn eip712_types(&self) -> &Self::Loader {
        &self.eip712_types_loader
    }
}

impl<'a, C, S, R, L1, L2> TargetCapabilityProvider for InvocationVerifier<'a, C, S, R, L1, L2> {
    type Caveat = C;
    type AdditionalProperties = S;

    fn target_capability(&self) -> &Delegation<Self::Caveat, Self::AdditionalProperties> {
        self.delegation
    }
}

impl<C, P> JsonLdObject for Delegation<C, P> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<C, P> JsonLdNodeObject for Delegation<C, P> {}

impl<C, S, E> ValidateClaims<E, AnyProofs> for Delegation<C, S> {
    fn validate_claims(&self, _: &E, proofs: &AnyProofs) -> ClaimsValidity {
        self.validate(proofs).map_err(InvalidClaims::other)
    }
}

impl<C, P> ssi_json_ld::Expandable for Delegation<C, P>
where
    C: Serialize,
    P: Serialize,
{
    type Error = JsonLdError;

    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json)
            .expand_with(ld, loader)
            .await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationValidationError {
    #[error("invalid proof purpose")]
    InvalidProofPurpose,
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationValidationError {
    #[error("invalid proof purpose")]
    InvalidProofPurpose,

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
    pub async fn sign<S>(
        self,
        suite: AnySuite,
        resolver: impl VerificationMethodResolver<Method = AnyMethod>,
        signer: S,
        mut proof_configuration: InputProofOptions<AnySuite>,
        target: &Uri,
    ) -> Result<AnyDataIntegrity<Invocation<P>>, SignatureError>
    where
        P: Serialize,
        S: Signer<AnyMethod>,
        S::MessageSigner: MessageSigner<AnySignatureAlgorithm>,
    {
        proof_configuration
            .extra_properties
            .insert("capability".into(), json_syntax::to_value(target).unwrap());

        suite
            .sign(self, resolver, signer, proof_configuration)
            .await
    }

    pub fn validate<C, Q>(
        &self,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<C, Q>,
        proofs: &Proofs<AnySuite>,
    ) -> Result<(), InvocationValidationError> {
        for proof in proofs.iter() {
            if proof.configuration().proof_purpose != ProofPurpose::CapabilityInvocation {
                return Err(InvocationValidationError::InvalidProofPurpose);
            }

            target_capability.validate_invocation_proof(proof)?
        }

        Ok(())
    }
}

impl<P> JsonLdObject for Invocation<P> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<P> JsonLdNodeObject for Invocation<P> {}

impl<P> ssi_json_ld::Expandable for Invocation<P>
where
    P: Serialize,
{
    type Error = JsonLdError;

    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json)
            .expand_with(ld, loader)
            .await
    }
}

impl<E, S> ValidateClaims<E, AnyProofs> for Invocation<S>
where
    E: TargetCapabilityProvider,
{
    fn validate_claims(&self, env: &E, proofs: &AnyProofs) -> ClaimsValidity {
        self.validate(env.target_capability(), proofs)
            .map_err(InvalidClaims::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_claims::VerificationParameters;
    use ssi_data_integrity::DataIntegrity;
    use ssi_dids_core::{example::ExampleDIDResolver, VerificationMethodDIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods::SingleSecretSigner;
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
        use ssi_data_integrity::ProofOptions;

        let dk = VerificationMethodDIDResolver::new(ExampleDIDResolver::new());
        let params = VerificationParameters::from_resolver(&dk);

        let alice_did = "did:example:foo";
        let alice_vm = UriBuf::new(format!("{}#key2", alice_did).into_bytes()).unwrap();
        let alice = SingleSecretSigner::new(JWK {
            key_id: Some(alice_vm.clone().into()),
            ..serde_json::from_str(include_str!("../../../tests/ed25519-2020-10-18.json")).unwrap()
        })
        .into_local();

        let bob_did = "did:example:bar";
        let bob_vm = UriBuf::new(format!("{}#key1", bob_did).into_bytes()).unwrap();
        let bob = SingleSecretSigner::new(JWK {
            key_id: Some(bob_vm.clone().into()),
            ..serde_json::from_str(include_str!("../../../tests/ed25519-2021-06-16.json")).unwrap()
        })
        .into_local();

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

        let ldpo_alice = ProofOptions::new(
            "2024-02-13T16:25:26Z".parse().unwrap(),
            alice_vm.clone().into_iri().into(),
            ProofPurpose::CapabilityDelegation,
            Default::default(),
        );
        let ldpo_bob = ProofOptions::new(
            "2024-02-13T16:25:26Z".parse().unwrap(),
            bob_vm.clone().into_iri().into(),
            ProofPurpose::CapabilityInvocation,
            Default::default(),
        );

        let signed_del = del
            .clone()
            .sign(
                AnySuite::pick(alice.secret(), ldpo_alice.verification_method.as_ref()).unwrap(),
                &dk,
                &alice,
                ldpo_alice.clone(),
                &[],
            )
            .await
            .unwrap();

        let signed_inv = inv
            .sign(
                AnySuite::pick(bob.secret(), ldpo_bob.verification_method.as_ref()).unwrap(),
                &dk,
                &bob,
                ldpo_bob,
                &signed_del.id,
            )
            .await
            .unwrap();

        // happy path
        assert!(signed_del.verify(&params).await.unwrap().is_ok());

        assert!(signed_inv
            .verify(InvocationVerifier::from_verifier_ref(
                &params,
                &signed_del.claims
            ))
            .await
            .unwrap()
            .is_ok());

        let bad_sig_del = DataIntegrity::new(
            Delegation {
                invoker: Some(uri!("did:someone_else").to_owned()),
                ..signed_del.claims.clone()
            },
            signed_del.proofs.clone(),
        );

        let mut bad_sig_inv = signed_inv.clone();
        bad_sig_inv.id = uri!("urn:different_id").to_owned();

        // invalid proof for data
        assert!(bad_sig_del.verify(&params).await.unwrap().is_err());
        assert!(bad_sig_inv
            .verify(InvocationVerifier::from_verifier_ref(
                &params,
                &signed_del.claims
            ))
            .await
            .unwrap()
            .is_err());

        // invalid cap attrs, invoker not matching
        let wrong_del = Delegation {
            invoker: Some(uri!("did:example:someone_else").to_owned()),
            ..del.clone()
        };
        let signed_wrong_del = wrong_del
            .sign(
                AnySuite::pick(alice.secret(), ldpo_alice.verification_method.as_ref()).unwrap(),
                &dk,
                &alice,
                ldpo_alice,
                &[],
            )
            .await
            .unwrap();
        assert!(signed_inv
            .verify(InvocationVerifier::from_verifier_ref(
                &params,
                &signed_wrong_del.claims
            ))
            .await
            .unwrap()
            .is_err());
    }
}
