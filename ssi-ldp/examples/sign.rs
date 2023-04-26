use chrono::Utc;
use json_ld::Compact;
use rdf_types::Literal;
use ssi_ldp::{
    suite::{DataIntegrityProof, Ed25519Signature2020},
    Sign, Verify,
};
use ssi_vc::Verifiable;
use static_iref::{iref, iri};
use treeldr_rust_macros::tldr;
use treeldr_rust_prelude::{
    json_ld::{self, syntax::Parse, Print, Process},
    ld::IntoJsonLd,
    locspan::Meta,
};

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

#[async_std::main]
async fn main() {
    let subject = schema::example::layout::SubjectExample {
        content: Some("Hello World!".to_string()),
    };

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
        Utc::now(),
        iri!("https://example.com/public_key").to_owned(),
        iri!("https://www.w3.org/2018/credentials#method").to_owned(),
    );

    let verifiable_credential: Verifiable<
        schema::example::layout::Credential,
        DataIntegrityProof<Ed25519Signature2020>,
    > = credential
        .sign(crypto_suite, &mut context, &Keyring, proof_options.clone())
        .expect("signing failed");

    verifiable_credential
        .verify(crypto_suite, &mut context, &Keyring, proof_options)
        .expect("verification failed")
        .into_result()
        .expect("invalid proof");

    let json_ld =
        Meta(verifiable_credential, ()).into_json_ld(rdf_types::vocabulary::no_vocabulary_mut());

    let mut loader: json_ld::FsLoader<iref::IriBuf, ()> =
        json_ld::FsLoader::new(|_, _, s| json_ld::syntax::Value::parse_str(s, |_| ()));
    loader.mount(
        iri!("https://www.w3.org/").to_owned(),
        "ssi-ldp/examples/assets/www.w3.org",
    );
    loader.mount(
        iri!("https://w3id.org/").to_owned(),
        "ssi-ldp/examples/assets/w3id.org",
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
        .process(&mut (), &mut loader, None)
        .await
        .expect("unable to process context");
    let compact = json_ld
        .compact(processed_context.as_ref(), &mut loader)
        .await
        .expect("unable to compact document");

    println!("{}", compact.pretty_print())
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
