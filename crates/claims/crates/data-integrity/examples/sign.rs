//! This example shows how to sign and verify a custom credential type crafted
//! with TreeLDR, using the `Ed25519Signature2020` cryptographic suite.
use std::borrow::Cow;

use chrono::Utc;
use hashbrown::HashMap;
use iref::{Iri, IriBuf, Uri, UriBuf};
use ssi_crypto::MessageSignatureError;
use ssi_data_integrity::{suites::Ed25519Signature2020, CryptographicSuiteInput};
use ssi_rdf::Expandable;
use ssi_verification_methods::{
    Controller, ControllerError, ControllerProvider, Ed25519VerificationKey2020, ProofPurpose,
    ProofPurposes, ReferenceOrOwnedRef, SignatureAlgorithm, SignatureError, Signer,
    VerificationMethod, VerificationMethodResolutionError, VerificationMethodResolver,
};
use static_iref::{iri, uri};

#[derive(Clone, linked_data::Serialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[ld(prefix("cred" = "https://www.w3.org/2018/credentials/v1"))]
pub struct Credential {
    #[ld(ignore)]
    #[serde(rename = "@context")]
    context: ssi_vc::Context,

    #[ld("cred:credentialSubject")]
    credential_subject: CredentialSubject,

    #[ld("cred:issuer")]
    issuer: linked_data::Ref<UriBuf>,

    #[ld("cred:issuanceDate")]
    issuance_date: xsd_types::DateTime,
}

impl ssi_json_ld::WithJsonLdContext for Credential {
    fn json_ld_context(&self) -> Cow<json_ld::syntax::Context> {
        Cow::Borrowed(self.context.as_ref())
    }
}

impl ssi_claims_core::Validate for Credential {
    fn is_valid(&self) -> bool {
        ssi_vc::Credential::is_valid_credential(self)
    }
}

impl ssi_vc::Credential for Credential {
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

    fn issuance_date(&self) -> chrono::prelude::DateTime<chrono::prelude::FixedOffset> {
        self.issuance_date.into()
    }
}

impl<E> Expandable<E> for Credential {
    type Error = std::convert::Infallible;
    type Expanded = Self;

    async fn expand(&self, _environment: &mut E) -> Result<Self::Expanded, Self::Error> {
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
        credential_subject,
        issuer: linked_data::Ref(uri!("http://example.com/issuer").to_owned()),
        issuance_date: chrono::Utc::now().into(),
    };

    // We do not use DIDs in this example. The `Keyring` type will store our
    // keys and controllers.
    let mut keyring = Keyring::default();

    // Create a new key `https://example.com/controller#key`.
    let mut csprng = rand::rngs::OsRng;
    let key_pair = ssi_verification_methods::ed25519_dalek::Keypair::generate(&mut csprng);
    keyring.insert_key_pair(
        Ed25519VerificationKey2020::from_public_key(
            iri!("https://example.com/controller#key").to_owned(),
            uri!("https://example.com/controller").to_owned(),
            key_pair.public,
        ),
        key_pair,
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
    let proof_options = ssi_data_integrity::ProofConfiguration::new(
        Utc::now().fixed_offset().into(),
        iri!("https://example.com/controller#key").to_owned().into(),
        ProofPurpose::Assertion,
        (),
    );

    // We use the Linked-Data-based cryptographic suite `Ed25519Signature2020`.
    // Linked-Data means that our credential will be projected into an RDF
    // dataset. We define here the vocabulary and interpretation for the RDF
    // dataset.
    let rdf = ssi_json_ld::JsonLdEnvironment::default();

    // Sign the credential.
    let verifiable_credential = Ed25519Signature2020
        .sign(credential, rdf, &keyring, proof_options.clone())
        .await
        .expect("signing failed");

    // Verify the generated verifiable credential.
    verifiable_credential
        .verify(&keyring)
        .await
        .expect("verification failed")
        .into_result()
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
            ssi_verification_methods::ed25519_dalek::Keypair,
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
        key_pair: ssi_verification_methods::ed25519_dalek::Keypair,
    ) {
        self.keys
            .insert(verification_key.id.clone(), (verification_key, key_pair));
    }
}

impl Signer<Ed25519VerificationKey2020, ssi_jwk::algorithm::EdDSA, ()> for Keyring {
    async fn sign<'a, 'o: 'a, 'm: 'a, A>(
        &'a self,
        algorithm: A,
        options: <A::Options as ssi_core::Referencable>::Reference<'o>,
        _issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, Ed25519VerificationKey2020>>,
        bytes: &'a [u8],
    ) -> Result<A::Signature, SignatureError>
    where
        A: 'a,
        A::Signature: 'a,
        A: SignatureAlgorithm<
            Ed25519VerificationKey2020,
            MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA,
            Protocol = (),
        >,
    {
        let id = match method {
            Some(ReferenceOrOwnedRef::Owned(key)) => key.id(),
            Some(ReferenceOrOwnedRef::Reference(id)) => id,
            None => return Err(SignatureError::MissingVerificationMethod),
        };

        match self.keys.get(id) {
            Some((method, key_pair)) => {
                algorithm
                    .sign(options, method, bytes, MessageSigner { method, key_pair })
                    .await
            }
            None => Err(SignatureError::UnknownVerificationMethod),
        }
    }
}

pub struct MessageSigner<'a> {
    method: &'a Ed25519VerificationKey2020,
    key_pair: &'a ssi_verification_methods::ed25519_dalek::Keypair,
}

impl<'a> ssi_crypto::MessageSigner<ssi_jwk::algorithm::EdDSA> for MessageSigner<'a> {
    async fn sign(
        self,
        _algorithm: ssi_jwk::algorithm::EdDSA,
        _protocol: (),
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(self.method.sign_bytes(message, self.key_pair))
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

impl VerificationMethodResolver<Ed25519VerificationKey2020> for Keyring {
    async fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        _issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, Ed25519VerificationKey2020>>,
    ) -> Result<
        ssi_verification_methods::Cow<'a, Ed25519VerificationKey2020>,
        VerificationMethodResolutionError,
    > {
        match method {
            Some(ReferenceOrOwnedRef::Owned(_key)) => {
                // If we get here, this means the VC embeds the public key used
                // to sign itself. It cannot really be trusted then.
                // It would be safer to either throw an error or at least fetch
                // the actual key using its id.
                todo!()
            }
            Some(ReferenceOrOwnedRef::Reference(id)) => match self.keys.get(id) {
                Some((key, _)) => Ok(ssi_verification_methods::Cow::Borrowed(key)),
                None => Err(VerificationMethodResolutionError::UnknownKey),
            },
            None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
        }
    }
}