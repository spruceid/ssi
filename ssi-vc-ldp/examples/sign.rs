use chrono::Utc;
use json_ld::{Compact, Print};
use rdf_types::{vocabulary::IriIndex, IndexVocabulary, IriVocabularyMut};
use ssi_crypto::ProofPurpose;
use ssi_vc_ldp::{suite::Ed25519Signature2020, DataIntegrity};
use static_iref::{iref, iri};
use treeldr_rust_macros::tldr;
use treeldr_rust_prelude::{
    json_ld::{self, syntax::Parse, Process},
    locspan::Meta,
    IntoJsonLd,
};

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
    let subject = schema::example::layout::SubjectExample {
        content: Some("Hello World!".to_string()),
    };

    let credential = schema::example::layout::Credential {
        subject: Some(subject),
    };

    let crypto_suite: ssi_vc_ldp::suite::Ed25519Signature2020 = Default::default();

    let proof_options = ssi_vc_ldp::ProofOptions::new(
        crypto_suite,
        Utc::now(),
        iri!("https://example.com/public_key").to_owned().into(),
        ProofPurpose::AssertionMethod,
    );

    let mut vocabulary: IndexVocabulary = Default::default();
    let mut interpretation = rdf_types::interpretation::Indexed::new();

    let verifiable_credential = DataIntegrity::sign_ld(
        &mut vocabulary,
        &mut interpretation,
        &Keyring,
        credential,
        Ed25519Signature2020,
        proof_options.clone(),
    )
    .expect("signing failed");

    verifiable_credential
        .verify(&Keyring)
        .await
        .expect("verification failed")
        .into_result()
        .expect("invalid proof");

    let json_ld = Meta(verifiable_credential, ()).into_json_ld(&mut vocabulary, &interpretation);

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

    let context = Meta(
        json_ld::syntax::context::Value::Many(vec![
            Meta(
                json_ld::syntax::Context::IriRef(
                    iref!("https://www.w3.org/2018/credentials/v1").to_owned(),
                ),
                (),
            ),
            Meta(
                json_ld::syntax::Context::IriRef(
                    iref!("https://w3id.org/security/data-integrity/v1").to_owned(),
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
    let compact = json_ld
        .compact_with(&mut vocabulary, processed_context.as_ref(), &mut loader)
        .await
        .expect("unable to compact document");

    println!("{}", compact.pretty_print())
}

pub struct Keyring;

impl<M> ssi_crypto::Signer<M> for Keyring {
    fn sign(&self, _method: &M, _bytes: &[u8]) -> Result<Vec<u8>, ssi_crypto::SignatureError> {
        Ok("unsigned".to_string().into_bytes())
    }
}

#[async_trait::async_trait]
impl<M> ssi_crypto::Verifier<M> for Keyring {
    async fn verify(
        &self,
        _method: &M,
        _purpose: ssi_crypto::ProofPurpose,
        _unsigned_bytes: &[u8],
        _signed_bytes: &[u8],
    ) -> Result<bool, ssi_crypto::VerificationError> {
        Ok(true)
    }
}
