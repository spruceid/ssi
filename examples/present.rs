// To generate text fixture:
// cargo run --example present < examples/vc.jsonld > examples/vp.jsonld

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/ed25519-2020-10-18.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let reader = std::io::BufReader::new(std::io::stdin());
    let vc: ssi::vc::Credential = serde_json::from_reader(reader).unwrap();
    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "holder": key.to_did().unwrap(),
        "verifiableCredential": vc
    });
    let mut vp: ssi::vc::Presentation = serde_json::from_value(vp).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = key.to_verification_method().unwrap();
    proof_options.verification_method = Some(verification_method);
    proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    proof_options.challenge = Some("example".to_string());
    let proof = vp.generate_proof(&key, &proof_options).await.unwrap();
    vp.add_proof(proof);
    let result = vp.verify(Some(proof_options)).await;
    if result.errors.len() > 0 {
        panic!("verify failed: {:#?}", result);
    }
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &vp).unwrap();
}
