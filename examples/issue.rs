// To generate text fixture:
// cargo run --example issue > examples/vc.jsonld

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let vc = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": ssi::ldp::now_ms(),
        "credentialSubject": {
            "id": "urn:uuid:".to_string() + &uuid::Uuid::new_v4().to_string()
        }
    });
    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:example:foo#key1".to_string();
    proof_options.verification_method = Some(verification_method);
    let proof = vc.generate_proof(&key, &proof_options).await.unwrap();
    vc.add_proof(proof);
    let result = vc.verify(None, &ssi::did::example::DIDExample).await;
    if result.errors.len() > 0 {
        panic!("verify failed: {:#?}", result);
    }
    let stdout_writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();
}
