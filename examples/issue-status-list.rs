// To generate test vector:
// cargo run --example issue-status-list > tests/statusList.json
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::v1::revocation::{StatusList2021, StatusList2021Credential, StatusList2021Subject},
    },
    jwk::JWK,
    verification_methods::SingleSecretSigner,
};
use ssi_claims::{vc::syntax::NonEmptyVec, VerificationParameters};
use ssi_dids::DIDResolver;
use static_iref::{iri, uri};

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    let key: JWK = serde_json::from_str(key_str).unwrap();
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    // DID resolver.
    let resolver = ssi::dids::example::ExampleDIDResolver::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(&resolver);

    let mut rl = StatusList2021::new(131072).unwrap();
    rl.set_status(1, true).unwrap();
    let rl_vc = StatusList2021Credential::new(
        Some(uri!("https://example.com/credentials/status/3").to_owned()),
        uri!("did:example:12345").to_owned().into(),
        xsd_types::DateTime::now_ms(),
        NonEmptyVec::new(StatusList2021Subject::StatusList2021(rl)),
    );

    let verification_method = iri!("did:example:12345#key1").into();

    let options = ProofOptions::from_method_and_options(verification_method, Default::default());
    let suite = AnySuite::pick(&key, options.verification_method.as_ref()).unwrap();
    let vc = suite
        .sign(rl_vc, &resolver, &signer, options)
        .await
        .unwrap();

    assert!(vc.verify(params).await.unwrap().is_ok());

    let stdout_writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();
}
