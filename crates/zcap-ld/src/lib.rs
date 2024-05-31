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
    data_integrity::{
        suite::{CryptographicSuiteInstance, CryptographicSuiteSigning, InputOptions},
        AnyDataIntegrity, AnyInputContext, AnyProofs, AnySignatureAlgorithm, AnySuite,
        CryptographicSuite, PreparedProof, PreparedProofs, Proofs,
    },
    vc::{Context, RequiredContext},
    ClaimsValidity, InvalidClaims, SignatureError, Validate, Verifiable,
};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject};
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

    pub fn validate(
        &self,
        proofs: &PreparedProofs<AnySuite>,
    ) -> Result<(), DelegationValidationError> {
        for proof in proofs.iter() {
            if proof.configuration().proof_purpose != ProofPurpose::CapabilityDelegation {
                return Err(DelegationValidationError::InvalidProofPurpose);
            }
        }

        Ok(())
    }

    pub fn validate_invocation_proof(
        &self,
        proof: &PreparedProof<AnySuite>,
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
        proof_configuration: InputOptions<AnySuite>,
        capability_chain: &[&str],
    ) -> Result<Verifiable<Self, AnyProofs>, SignatureError>
    where
        C: Serialize,
        P: Serialize,
        S: Signer<AnyMethod>,
        S::MessageSigner: MessageSigner<AnySignatureAlgorithm>,
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
    pub async fn sign_with<D, E, R, S>(
        self,
        suite: D,
        environment: E,
        resolver: R,
        signer: S,
        mut proof_configuration: InputOptions<D>,
        capability_chain: &[&str],
    ) -> Result<Verifiable<Self, Proofs<D>>, SignatureError>
    where
        D: CryptographicSuiteInstance<Self, E> + CryptographicSuiteSigning<R, S>,
    {
        proof_configuration.extra_properties.insert(
            "capabilityChain".into(),
            json_syntax::to_value(capability_chain).unwrap(),
        );

        if proof_configuration.proof_purpose != ProofPurpose::CapabilityDelegation {
            // TODO invalid proof purpose.
        }

        suite
            .sign(self, environment, resolver, signer, proof_configuration)
            .await
    }
}

impl<C, P> JsonLdObject for Delegation<C, P> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<C, P> JsonLdNodeObject for Delegation<C, P> {}

impl<C, S, E> Validate<E, AnyProofs> for Delegation<C, S> {
    fn validate(&self, _: &E, proofs: &PreparedProofs<AnySuite>) -> ClaimsValidity {
        self.validate(proofs).map_err(InvalidClaims::other)
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
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    // type Resource = I::Resource;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json).expand(environment).await
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
        mut proof_configuration: InputOptions<AnySuite>,
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

        Ok(Verifiable::unprepare(
            suite
                .sign(
                    self,
                    AnyInputContext::default(),
                    resolver,
                    signer,
                    proof_configuration,
                )
                .await?,
        ))
    }

    pub fn validate<C, Q>(
        &self,
        // TODO make this a list for delegation chains
        target_capability: &Delegation<C, Q>,
        proofs: &PreparedProofs<AnySuite>,
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
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<P> JsonLdNodeObject for Invocation<P> {}

impl<P, E, V, L> ssi_rdf::Expandable<E> for Invocation<P>
where
    P: Serialize,
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    // type Resource = I::Resource;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = json_syntax::to_value(self).unwrap();
        ssi_json_ld::CompactJsonLd(json).expand(environment).await
    }
}

impl<S, C, Q> Validate<Delegation<C, Q>, AnyProofs> for Invocation<S> {
    fn validate(
        &self,
        target_capability: &Delegation<C, Q>,
        proofs: &PreparedProofs<AnySuite>,
    ) -> ClaimsValidity {
        self.validate(target_capability, proofs)
            .map_err(InvalidClaims::other)
    }
}

// impl<P> VerifiableInvocation<P> {

//     #[allow(unused, unreachable_code)]
//     pub async fn verify<C, Q>(
//         &self,
//         // TODO make this a list for delegation chains
//         target_capability: &Delegation<C, Q>,
//         verifier: &impl VerificationMethodResolver<Method = AnyMethod>,
//     ) -> Result<Verification, InvocationVerificationError>
//     where
//         P: Clone + Serialize,
//     {
//         let vc = self
//             .clone()
//             .into_verifiable_claims(target_capability)
//             .await?;
//         vc.verify(verifier).await.map_err(Into::into)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_claims::{UnprepareProof, VerifiableClaims};
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
            .unwrap()
            .into_verifiable()
            .await
            .unwrap();

        // happy path
        assert!(signed_del.verify(&dk).await.unwrap().is_ok());

        assert!(signed_inv
            .verify_with(&dk, &signed_del.claims)
            .await
            .unwrap()
            .is_ok());

        let bad_sig_del = DataIntegrity::new(
            Delegation {
                invoker: Some(uri!("did:someone_else").to_owned()),
                ..signed_del.claims.clone()
            },
            signed_del.proof.clone().unprepare(),
        )
        .into_verifiable()
        .await
        .unwrap();
        let bad_sig_inv = signed_inv
            .clone()
            .tamper(AnyInputContext::default(), |mut inv| {
                inv.id = uri!("urn:different_id").to_owned();
                inv
            })
            .await
            .unwrap();

        // invalid proof for data
        assert!(bad_sig_del.verify(&dk).await.unwrap().is_err());
        assert!(bad_sig_inv
            .verify_with(&dk, &signed_del.claims)
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
            .verify_with(&dk, &signed_wrong_del.claims)
            .await
            .unwrap()
            .is_err());
    }
}
