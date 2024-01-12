//! This example shows how to sign and verify a custom credential type crafted
//! with TreeLDR, using the `Ed25519Signature2020` cryptographic suite.
use std::future;

use chrono::Utc;
use hashbrown::HashMap;
use iref::{Iri, IriBuf};
use json_ld::{syntax::Parse, Compact, Print, Process};
use linked_data::LinkedData;
use locspan::Meta;
use rdf_types::{vocabulary::IriIndex, IndexVocabulary, IriVocabularyMut};
use ssi_core::futures::FailibleFuture;
use ssi_crypto::MessageSignatureError;
use ssi_vc_ldp::{suite::Ed25519Signature2020, DataIntegrity, CryptographicSuiteInput};
use ssi_verification_methods::{
    Controller, ControllerError, ControllerProvider, Ed25519VerificationKey2020, ProofPurpose,
    ProofPurposes, ReferenceOrOwnedRef, SignatureAlgorithm, SignatureError, Signer,
    VerificationError, VerificationMethod, VerificationMethodResolutionError,
    VerificationMethodResolver, Verifier,
};
use static_iref::{iri, iri_ref, uri};

#[derive(linked_data::Serialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Credential {
    #[ld("sec:credentialSubject")]
    subject: CredentialSubject,
}

#[derive(linked_data::Serialize)]
#[ld(prefix("ex" = "https://example.org/sign#"))]
pub struct CredentialSubject {
    #[ld("ex:content")]
    content: String,
}

#[async_std::main]
async fn main() {
    // Credential subject.
    let subject = CredentialSubject {
        content: "Hello World!".to_string(),
    };

    // Credential built from the subject.
    let credential = Credential { subject };

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
    let proof_options = ssi_vc_ldp::ProofConfiguration::new(
        Utc::now().fixed_offset().into(),
        iri!("https://example.com/controller#key").to_owned().into(),
        ProofPurpose::Assertion,
        ()
    );

    // We use the Linked-Data-based cryptographic suite `Ed25519Signature2020`.
    // Linked-Data means that our credential will be projected into an RDF
    // dataset. We define here the vocabulary and interpretation for the RDF
    // dataset.
    let mut vocabulary: IndexVocabulary = Default::default();
    let mut interpretation = rdf_types::interpretation::Indexed::new();
    let rdf = ssi_vc_ldp::LinkedDataInput::new(vocabulary, interpretation);

    // Sign the credential.
    let verifiable_credential = Ed25519Signature2020.sign(
        credential,
        rdf,
        &keyring,
        proof_options.clone()
    ).await
    .expect("signing failed");

    // Verify the generated verifiable credential.
    verifiable_credential
        .verify(&keyring)
        .await
        .expect("verification failed")
        .into_result()
        .expect("invalid proof");

    // Put the verifiable credential in JSON-LD form.
    // json_ld::as
    let json_ld =
        json_ld::ser::serialize_with(&mut vocabulary, &mut interpretation, &verifiable_credential)
            .unwrap();

    // The generated JSON-LD is in expanded form. We want to compact it.
    // We will use the context definitions defined in the
    // `ssi-vc-ldp/examples/assets` folder.
    let mut loader: json_ld::FsLoader<IriIndex, ()> =
        json_ld::FsLoader::new(|_, _, s| json_ld::syntax::Value::parse_str(s, |_| ()));
    loader.mount(
        vocabulary.insert(iri!("https://www.w3.org/")),
        "ssi-vc-ldp/examples/assets/www.w3.org",
    );
    loader.mount(
        vocabulary.insert(iri!("https://w3id.org/")),
        "ssi-vc-ldp/examples/assets/w3id.org",
    );

    // Pick and process the LD context used for compaction.
    let context = Meta(
        json_ld::syntax::Context::Many(vec![
            Meta(
                json_ld::syntax::ContextEntry::IriRef(
                    iri_ref!("https://w3id.org/security/v1").to_owned(),
                ),
                (),
            ),
            Meta(
                json_ld::syntax::ContextEntry::IriRef(
                    iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1").to_owned(),
                ),
                (),
            ),
        ]),
        (),
    );
    let processed_context = context
        .process(&mut vocabulary, &mut loader, None)
        .await
        .expect("unable to process context");

    // Compact the JSON-LD document.
    let compact = Meta::none(json_ld)
        .compact_with(&mut vocabulary, processed_context.as_ref(), &mut loader)
        .await
        .expect("unable to compact document");

    println!("{}", compact.pretty_print())
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
    async fn sign<
        'a,
        'o: 'a,
        'm: 'a,
        A,
    >(
        &'a self,
        algorithm: A,
        options: <A::Options as ssi_verification_methods::Referencable>::Reference<'o>,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, Ed25519VerificationKey2020>>,
        bytes: &'a [u8],
    ) -> Result<A::Signature, SignatureError>
    where
        A: 'a,
        A::Signature: 'a,
        A: SignatureAlgorithm<Ed25519VerificationKey2020, MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA, Protocol = ()>
    {
            let id = match method {
                Some(ReferenceOrOwnedRef::Owned(key)) => key.id(),
                Some(ReferenceOrOwnedRef::Reference(id)) => id,
                None => return Err(SignatureError::MissingVerificationMethod),
            };
    
            match self.keys.get(id) {
                Some((method, key_pair)) => {
                    algorithm.sign(
                        options,
                        method,
                        bytes,
                        MessageSigner { method, key_pair },
                    ).await
                },
                None => Err(SignatureError::UnknownVerificationMethod),
            }
    }
}

pub struct MessageSigner<'a> {
    method: &'a Ed25519VerificationKey2020,
    key_pair: &'a ssi_verification_methods::ed25519_dalek::Keypair,
}

impl<'a> ssi_crypto::MessageSigner<ssi_jwk::algorithm::EdDSA> for MessageSigner<'a> {
    async fn sign(self, _algorithm: ssi_jwk::algorithm::EdDSA, _protocol: (), message: &[u8]) -> Result<Vec<u8>, MessageSignatureError> {
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
    ) -> Result<ssi_verification_methods::Cow<'a, Ed25519VerificationKey2020>, VerificationMethodResolutionError> {
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
