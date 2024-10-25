//! When too many lifetime requirements are added to async fns in traits, the
//! compiler may get confused, triggering this issue:
//! <https://github.com/rust-lang/rust/issues/100013>
//! This test ensures that the Rust compiler is able to prove that the
//! `CryptographicSuite::sign` returns a future that is `Send` without
//! triggering the issue.
mod vcdm_v1_sign;
mod vcdm_v2_sign;

use serde::{Deserialize, Serialize};
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::v1::JsonCredential,
    },
    dids::{DIDResolver, DIDJWK},
    verification_methods::SingleSecretSigner,
    JWK,
};
use ssi_claims::vc::syntax::NonEmptyVec;
use static_iref::uri;
use std::future::Future;

fn assert_send(f: impl Send + Future) {
    drop(f)
}

#[test]
fn data_integrity_sign_is_send() {
    let credential = JsonCredential::<Claims>::new(
        Some(uri!("https://example.org/#CredentialId").to_owned()), // id
        uri!("https://example.org/#Issuer").to_owned().into(),      // issuer
        xsd_types::DateTime::now(),                                 // issuance date
        NonEmptyVec::new(Claims {
            name: "name".into(),
            email: "email@example.com".into(),
        }),
    );

    let key = JWK::generate_p256(); // requires the `p256` feature.
    let did = DIDJWK::generate_url(&key.to_public());
    let vm_resolver = DIDJWK.into_vm_resolver();
    let signer = SingleSecretSigner::new(key.clone()).into_local();
    let verification_method = did.into_iri().into();

    let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
        .expect("could not find appropriate cryptosuite");

    assert_send(cryptosuite.sign(
        credential,
        &vm_resolver,
        &signer,
        ProofOptions::from_method(verification_method),
    ))
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "https://example.org/#name")]
    name: String,

    #[serde(rename = "https://example.org/#email")]
    email: String,
}
