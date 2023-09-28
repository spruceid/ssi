// To generate test vectors:
// cargo run --example issue ldp > examples/vc.jsonld
// cargo run --example issue jwt > examples/vc.jwt

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = &ssi::did::example::DIDExample;
    let vc = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": ssi::ldp::now_ns(),
        "credentialSubject": {
            "id": "urn:uuid:".to_string() + &uuid::Uuid::new_v4().to_string()
        }
    });
    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:example:foo#key1".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    let proof_format = std::env::args().nth(1);
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    match &proof_format.unwrap()[..] {
        "ldp" => {
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
        "jwt" => {
            proof_options.created = None;
            proof_options.checks = None;
            let jwt = vc
                .generate_jwt(Some(&key), &proof_options, resolver)
                .await
                .unwrap();
            let result =
                ssi::vc::Credential::verify_jwt(&jwt, None, resolver, &mut context_loader).await;
            if !result.errors.is_empty() {
                panic!("verify failed: {:#?}", result);
            }
            print!("{}", jwt);
        }
        format => panic!("unknown proof format: {}", format),
    }
}
