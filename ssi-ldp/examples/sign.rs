use chrono::Utc;
use rdf_types::Literal;
use ssi_ldp::{Sign, Verify};
use static_iref::iri;
use treeldr_rust_macros::tldr;

#[tldr("ssi-ldp/examples/sign.tldr", "ssi-vc/src/schema.ttl")]
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

fn main() {
    let subject = schema::example::layout::SubjectExample { content: None };

    let credential = schema::example::layout::Credential {
        subject: Some(subject),
    };

    let crypto_suite: ssi_ldp::suite::Ed25519Signature2020 = Default::default();

    let mut context = ssi_ldp::LinkedDataCredentialContext::<Literal, (), _, _>::new(
        rdf_types::vocabulary::no_vocabulary_mut(),
        rdf_types::generator::Blank::new(),
    );

    let proof_options = ssi_ldp::suite::ProofOptions::new(
        crypto_suite,
        None,
        Utc::now().naive_utc(),
        iri!("https://example.com/public_key").to_owned(),
        iri!("https://www.w3.org/2018/credentials#method").to_owned(),
    );

    let verifiable_credential = credential
        .sign(crypto_suite, &mut context, &Keyring, proof_options.clone())
        .expect("signing failed");

    // TODO: to JSON-LD

    verifiable_credential
        .verify(crypto_suite, &mut context, &Keyring, proof_options)
        .expect("verification failed")
        .into_result()
        .expect("invalid proof");
}

pub struct Keyring;

impl<M> ssi_ldp::SignerProvider<M> for Keyring {
    type Signer<'a> = Signer;

    fn get_signer(&self, _method: &M) -> Self::Signer<'_> {
        Signer
    }
}

impl<M> ssi_ldp::VerifierProvider<M> for Keyring {
    type Verifier<'a> = Verifier;

    fn get_verifier(&self, _method: &M) -> Self::Verifier<'_> {
        Verifier
    }
}

pub struct Signer;

impl ssi_ldp::Signer for Signer {
    fn sign(&self, _algorithm: ssi_ldp::Algorithm, _bytes: &[u8]) -> Vec<u8> {
        "unsigned".to_string().into_bytes()
    }
}
pub struct Verifier;

impl ssi_ldp::Verifier for Verifier {
    fn verify(
        &self,
        _algorithm: ssi_ldp::Algorithm,
        _unsigned_bytes: &[u8],
        _signed_bytes: &[u8],
    ) -> bool {
        true
    }
}
