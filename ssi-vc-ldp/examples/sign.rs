//! This example shows how to sign and verify a custom credential type crafted
//! with TreeLDR, using the `Ed25519Signature2020` cryptographic suite.
use chrono::Utc;
use hashbrown::HashMap;
use iref::{Iri, IriBuf};
use json_ld::{Compact, Print};
use rdf_types::{vocabulary::IriIndex, IndexVocabulary, IriVocabularyMut};
use ssi_crypto::{ProofPurpose, ProofPurposes};
use ssi_vc_ldp::{suite::Ed25519Signature2020, DataIntegrity};
use ssi_verification_methods::{
    Controller, ControllerError, ControllerProvider, Ed25519VerificationKey2020, ReferenceOrOwned,
    VerificationMethod,
};
use static_iref::{iref, iri};
use treeldr_rust_macros::tldr;
use treeldr_rust_prelude::{
    json_ld::{self, syntax::Parse, Process},
    locspan::Meta,
    IntoJsonLd,
};

// Import all the TreeLDR schema definitions.
#[tldr("ssi-vc-ldp/examples/sign.tldr", "ssi-vc/src/schema/cred.ttl")]
mod schema {
    #[prefix("https://treeldr.org/")]
    pub use ssi_vc::schema::tldr;

    #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
    pub use ssi_vc::schema::rdfs;

    #[prefix("http://www.w3.org/2001/XMLSchema#")]
    pub use ssi_vc::schema::xsd;

    #[prefix("https://www.w3.org/2018/credentials#")]
    pub use ssi_vc::schema::cred;

    #[prefix("https://example.com/")]
    pub mod example {}
}

#[async_std::main]
async fn main() {
    // Credential subject.
    let subject = schema::example::layout::SubjectExample {
        content: Some("Hello World!".to_string()),
    };

    // Credential built from the subject.
    let credential = schema::example::layout::Credential {
        subject: Some(subject),
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
            iri!("https://example.com/controller").to_owned(),
            key_pair.public,
        ),
        key_pair,
    );

    // Create the key controller and declare our key with its purposes.
    let mut controller = KeyController::default();
    controller.insert_key(
        iri!("https://example.com/controller#key").to_owned(),
        ProofPurpose::AssertionMethod
            | ProofPurpose::Authentication
            | ProofPurpose::CapabilityDelegation,
    );
    keyring.insert_controller(
        iri!("https://example.com/controller").to_owned(),
        controller,
    );

    // Signature options, defining the crypto suite, signature date,
    // signing key and proof purpose.
    let proof_options = ssi_vc_ldp::ProofOptions::new(
        Ed25519Signature2020,
        Utc::now(),
        iri!("https://example.com/controller#key").to_owned().into(),
        ProofPurpose::AssertionMethod,
    );

    // We use the Linked-Data-based cryptographic suite `Ed25519Signature2020`.
    // Linked-Data means that our credential will be projected into an RDF
    // dataset. We define here the vocabulary and interpretation for the RDF
    // dataset.
    let mut vocabulary: IndexVocabulary = Default::default();
    let mut interpretation = rdf_types::interpretation::Indexed::new();

    // Sign the credential.
    let verifiable_credential = DataIntegrity::sign_ld(
        &mut vocabulary,
        &mut interpretation,
        &keyring,
        credential,
        Ed25519Signature2020,
        proof_options.clone(),
    )
    .expect("signing failed");

    // Verify the generated verifiable credential.
    verifiable_credential
        .verify(&keyring)
        .await
        .expect("verification failed")
        .into_result()
        .expect("invalid proof");

    // Put the verifiable credential in JSON-LD form.
    let json_ld = Meta(verifiable_credential, ()).into_json_ld(&mut vocabulary, &interpretation);

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
        json_ld::syntax::context::Value::Many(vec![
            Meta(
                json_ld::syntax::Context::IriRef(iref!("https://w3id.org/security/v1").to_owned()),
                (),
            ),
            Meta(
                json_ld::syntax::Context::IriRef(
                    iref!("https://w3id.org/security/suites/ed25519-2020/v1").to_owned(),
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
    let compact = json_ld
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
    fn allows_verification_method(
        &self,
        id: Iri,
        proof_purposes: ssi_crypto::ProofPurposes,
    ) -> bool {
        self.keys
            .get(&id)
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

impl ssi_crypto::Signer<ReferenceOrOwned<Ed25519VerificationKey2020>> for Keyring {
    fn sign(
        &self,
        method: &ReferenceOrOwned<Ed25519VerificationKey2020>,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ssi_crypto::SignatureError> {
        let id = match method {
            ReferenceOrOwned::Owned(key) => key.id(),
            ReferenceOrOwned::Reference(id) => id.iri(),
        };

        match self.keys.get(&id) {
            Some(key) => {
                use ssi_verification_methods::ed25519_dalek::{Signature, Signer};
                Ok(Signature::to_bytes(key.1.sign(bytes)).to_vec())
            }
            None => Err(ssi_crypto::SignatureError::UnknownVerificationMethod),
        }
    }
}

#[async_trait::async_trait]
impl ControllerProvider for Keyring {
    type Controller<'a> = &'a KeyController;

    async fn get_controller(
        &self,
        id: Iri<'_>,
    ) -> Result<Option<Self::Controller<'_>>, ControllerError> {
        Ok(self.controllers.get(&id.to_owned()))
    }
}

#[async_trait::async_trait]
impl ssi_crypto::Verifier<ReferenceOrOwned<Ed25519VerificationKey2020>> for Keyring {
    async fn verify(
        &self,
        method: &ReferenceOrOwned<Ed25519VerificationKey2020>,
        purpose: ssi_crypto::ProofPurpose,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, ssi_crypto::VerificationError> {
        match method {
            ReferenceOrOwned::Owned(key) => {
                // If we get here, this means the VC embeds the public key used
                // to sign itself. It cannot really be trusted then.
                // It would be safer to either throw an error or at least fetch
                // the actual key using its id.
                key.verify(self, purpose, bytes, signature).await
            }
            ReferenceOrOwned::Reference(id) => match self.keys.get(&id.iri()) {
                Some(key) => key.0.verify(self, purpose, bytes, signature).await,
                None => Err(ssi_crypto::VerificationError::UnknownKey),
            },
        }
    }
}
