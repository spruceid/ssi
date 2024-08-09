//! This example shows how to sign and verify a custom credential type crafted
//! with TreeLDR, using the `Ed25519Signature2020` cryptographic suite.
use iref::{Iri, IriBuf, Uri, UriBuf};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rand_chacha::rand_core::SeedableRng;
use ssi_claims_core::{SignatureError, VerificationParameters};
use ssi_data_integrity::{suites::Ed25519Signature2020, CryptographicSuite, ProofOptions};
use ssi_json_ld::{Expandable, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, VocabularyMut};
use ssi_verification_methods::{
    Controller, ControllerError, ControllerProvider, Ed25519VerificationKey2020, MethodWithSecret,
    ProofPurpose, ProofPurposes, ReferenceOrOwnedRef, Signer, VerificationMethod,
    VerificationMethodResolutionError, VerificationMethodResolver,
};
use static_iref::{iri, uri};
use std::{borrow::Cow, collections::HashMap, sync::Arc};
use xsd_types::{DateTime, DateTimeStamp};

#[derive(Clone, linked_data::Serialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[ld(prefix("cred" = "https://www.w3.org/2018/credentials/v1"))]
pub struct Credential {
    #[ld(ignore)]
    #[serde(rename = "@context")]
    context: ssi_vc::v1::Context,

    #[ld(ignore)]
    #[serde(rename = "type")]
    type_: ssi_vc::v1::JsonCredentialTypes,

    #[ld("cred:credentialSubject")]
    credential_subject: CredentialSubject,

    #[ld("cred:issuer")]
    issuer: linked_data::Ref<UriBuf>,

    #[ld("cred:issuanceDate")]
    issuance_date: DateTime,
}

impl ssi_json_ld::JsonLdObject for Credential {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl ssi_json_ld::JsonLdNodeObject for Credential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.type_.to_json_ld_types()
    }
}

impl<E, P> ssi_claims_core::ValidateClaims<E, P> for Credential
where
    E: ssi_claims_core::DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ssi_claims_core::ClaimsValidity {
        ssi_vc::v1::Credential::validate_credential(self, env)
    }
}

impl ssi_vc::v1::Credential for Credential {
    type Subject = CredentialSubject;
    type Issuer = Uri;
    type Status = std::convert::Infallible;
    type RefreshService = std::convert::Infallible;
    type TermsOfUse = std::convert::Infallible;
    type Evidence = std::convert::Infallible;
    type Schema = std::convert::Infallible;

    fn credential_subjects(&self) -> &[Self::Subject] {
        std::slice::from_ref(&self.credential_subject)
    }

    fn issuer(&self) -> &Self::Issuer {
        &self.issuer.0
    }

    fn issuance_date(&self) -> Option<DateTime> {
        Some(self.issuance_date)
    }
}

impl Expandable for Credential {
    type Error = std::convert::Infallible;
    type Expanded<I, V> = Self
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        _ld: &mut LdEnvironment<V, I>,
        _loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        Ok(self.clone())
    }
}

#[derive(Clone, linked_data::Serialize, serde::Serialize)]
#[ld(prefix("ex" = "https://example.org/sign#"))]
pub struct CredentialSubject {
    #[ld("ex:content")]
    #[serde()]
    content: String,
}

#[async_std::main]
async fn main() {
    // Credential subject.
    let credential_subject = CredentialSubject {
        content: "Hello World!".to_string(),
    };

    // Credential built from the subject.
    let credential = Credential {
        context: Default::default(),
        type_: Default::default(),
        credential_subject,
        issuer: linked_data::Ref(uri!("http://example.com/issuer").to_owned()),
        issuance_date: chrono::Utc::now().into(),
    };

    // We do not use DIDs in this example. The `Keyring` type will store our
    // keys and controllers.
    let mut keyring = Keyring::default();

    // Create a new key `https://example.com/controller#key`.
    let mut csprng = rand_chacha::ChaCha8Rng::from_entropy();
    let secret_key = ssi_verification_methods::ed25519_dalek::SigningKey::generate(&mut csprng);
    keyring.insert_key_pair(
        Ed25519VerificationKey2020::from_public_key(
            iri!("https://example.com/controller#key").to_owned(),
            uri!("https://example.com/controller").to_owned(),
            secret_key.verifying_key(),
        ),
        secret_key,
    );

    // Create the key controller and declare our key with its purposes.
    let mut controller = KeyController::default();
    controller.insert_key(
        iri!("https://example.com/controller#key").to_owned(),
        ProofPurpose::Assertion | ProofPurpose::Authentication | ProofPurpose::CapabilityDelegation,
    );
    keyring.insert_controller(
        iri!("https://example.com/controller").to_owned(),
        controller,
    );

    // Signature options, defining the crypto suite, signature date,
    // signing key and proof purpose.
    let proof_options = ProofOptions::new(
        DateTimeStamp::now(),
        iri!("https://example.com/controller#key").to_owned().into(),
        ProofPurpose::Assertion,
        (),
    );

    // Sign the credential.
    let verifiable_credential = Ed25519Signature2020
        .sign(credential, &keyring, &keyring, proof_options.clone())
        .await
        .expect("signing failed");

    // Verify the generated verifiable credential.
    verifiable_credential
        .verify(VerificationParameters::from_resolver(keyring))
        .await
        .expect("verification failed")
        .expect("invalid proof");

    // Put the verifiable credential in JSON(-LD) form.
    println!(
        "{}",
        serde_json::to_string_pretty(&verifiable_credential).unwrap()
    )
}

/// Simple key controller, just for this example.
#[derive(Default)]
pub struct KeyController {
    // Lists the keys controlled by this controller and their allowed purposes.
    keys: HashMap<IriBuf, ProofPurposes>,
}

impl KeyController {
    pub fn insert_key(&mut self, id: IriBuf, purposes: ProofPurposes) {
        self.keys.insert(id, purposes);
    }
}

impl Controller for KeyController {
    fn allows_verification_method(&self, id: &Iri, proof_purposes: ProofPurposes) -> bool {
        self.keys
            .get(id)
            .is_some_and(|p| p.contains_all(proof_purposes))
    }
}

/// Simple keyring implementation, just for this example.
#[derive(Default)]
pub struct Keyring {
    // Lists the known controllers.
    controllers: HashMap<IriBuf, KeyController>,

    // Lists the known verification methods, including the private part of the
    // key pair. In this example, we only use the `Ed25519VerificationKey2020`
    // verification method.
    keys: HashMap<
        IriBuf,
        (
            Ed25519VerificationKey2020,
            Arc<ssi_verification_methods::ed25519_dalek::SigningKey>,
        ),
    >,
}

impl Keyring {
    pub fn insert_controller(&mut self, id: IriBuf, controller: KeyController) {
        self.controllers.insert(id, controller);
    }

    pub fn insert_key_pair(
        &mut self,
        verification_key: Ed25519VerificationKey2020,
        key_pair: ssi_verification_methods::ed25519_dalek::SigningKey,
    ) {
        self.keys.insert(
            verification_key.id.clone(),
            (verification_key, Arc::new(key_pair)),
        );
    }
}

impl Signer<Ed25519VerificationKey2020> for Keyring {
    type MessageSigner = MethodWithSecret<
        Ed25519VerificationKey2020,
        ssi_verification_methods::ed25519_dalek::SigningKey,
    >;

    async fn for_method(
        &self,
        method: Cow<'_, Ed25519VerificationKey2020>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(self
            .keys
            .get(method.id())
            .map(|(method, key_pair)| MethodWithSecret::new(method.clone(), key_pair.clone())))
    }
}

impl ControllerProvider for Keyring {
    type Controller<'a> = &'a KeyController;

    async fn get_controller<'a>(
        &'a self,
        id: &'a Iri,
    ) -> Result<Option<Self::Controller<'a>>, ControllerError> {
        Ok(self.controllers.get(&id.to_owned()))
    }
}

impl VerificationMethodResolver for Keyring {
    type Method = Ed25519VerificationKey2020;

    async fn resolve_verification_method_with(
        &self,
        _issuer: Option<&Iri>,
        method: Option<ReferenceOrOwnedRef<'_, Ed25519VerificationKey2020>>,
        _options: ssi_verification_methods::ResolutionOptions,
    ) -> Result<Cow<Ed25519VerificationKey2020>, VerificationMethodResolutionError> {
        match method {
            Some(ReferenceOrOwnedRef::Owned(_key)) => {
                // If we get here, this means the VC embeds the public key used
                // to sign itself. It cannot really be trusted then.
                // It would be safer to either throw an error or at least fetch
                // the actual key using its id.
                todo!()
            }
            Some(ReferenceOrOwnedRef::Reference(id)) => match self.keys.get(id) {
                Some((key, _)) => Ok(Cow::Borrowed(key)),
                None => Err(VerificationMethodResolutionError::UnknownKey),
            },
            None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
        }
    }
}
