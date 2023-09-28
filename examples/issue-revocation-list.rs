// To generate test vectors:
// cargo run --example issue-revocation-list > tests/revocationList.json

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    use ssi::vc::{Credential, Issuer, URI};
    use std::convert::TryFrom;
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = &ssi::did::example::DIDExample;
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    use ssi::revocation::{
        RevocationList2020, RevocationList2020Credential, RevocationList2020Subject,
    };
    let mut rl = RevocationList2020::default();
    rl.set_status(1, true).unwrap();
    let rl_vc = RevocationList2020Credential {
        issuer: Issuer::URI(URI::String("did:example:foo".to_string())),
        id: URI::String("https://example.test/revocationList.json".to_string()),
        credential_subject: RevocationList2020Subject::RevocationList2020(rl),
        more_properties: serde_json::Value::Null,
    };
    let mut vc = Credential::try_from(rl_vc).unwrap();
    vc.issuance_date = Some(ssi::vc::VCDateTime::from(ssi::ldp::now_ns()));
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:example:foo#key1".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
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
