// To generate test vector:
// cargo run --example issue-status-list > tests/statusList.json

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    use ssi::vc::{Credential, Issuer, URI};
    use std::convert::TryFrom;
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = &ssi::did::example::DIDExample;
    use ssi::revocation::{StatusList2021, StatusList2021Credential, StatusList2021Subject};
    let mut rl = StatusList2021::new(131072).unwrap();
    rl.set_status(1, true).unwrap();
    let rl_vc = StatusList2021Credential {
        issuer: Issuer::URI(URI::String("did:example:12345".to_string())),
        id: URI::String("https://example.com/credentials/status/3".to_string()),
        credential_subject: StatusList2021Subject::StatusList2021(rl),
        more_properties: serde_json::Value::Null,
    };
    let mut vc = Credential::try_from(rl_vc).unwrap();
    vc.issuance_date = Some(ssi::vc::VCDateTime::from(ssi::ldp::now_ns()));
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:example:12345#key1".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let proof = vc
        .generate_proof(&key, &proof_options, resolver, &mut context_loader)
        .await
        .unwrap();
    vc.add_proof(proof);
    let result = vc.verify(None, resolver, &mut context_loader).await;
    if !result.errors.is_empty() {
        panic!("verify failed: {:#?}", result);
    }
    let stdout_writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();
}
