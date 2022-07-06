// To generate test vectors:
// cargo run --example present ldp ldp < examples/vc.jsonld > examples/vp.jsonld
// cargo run --example present ldp jwt < examples/vc.jsonld > examples/vp.jwt
// cargo run --example present jwt ldp < examples/vc.jwt > examples/vp-jwtvc.jsonld
// cargo run --example present jwt jwt < examples/vc.jwt > examples/vp-jwtvc.jwt

#[async_std::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let proof_format_in = args.next().unwrap();
    let proof_format_out = args.next().unwrap();

    let key_str = include_str!("../tests/ed25519-2020-10-18.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let resolver = &ssi::did::example::DIDExample;
    let vc = match &proof_format_in[..] {
        "ldp" => {
            let vc_ldp = serde_json::from_reader(reader).unwrap();
            ssi::vc::CredentialOrJWT::Credential(vc_ldp)
        }
        "jwt" => {
            use std::io::Read;
            let mut vc_jwt = String::new();
            reader.read_to_string(&mut vc_jwt).unwrap();
            if vc_jwt.starts_with('{') {
                panic!("Input must be a compact JWT");
            }
            ssi::vc::CredentialOrJWT::JWT(vc_jwt)
        }
        format => panic!("unknown input proof format: {}", format),
    };

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "holder": "did:example:foo",
        "verifiableCredential": vc
    });
    let mut vp: ssi::vc::Presentation = serde_json::from_value(vp).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:example:foo#key2".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    proof_options.challenge = Some("example".to_string());

    let mut context_loader = ssi::jsonld::ContextLoader::default();
    match &proof_format_out[..] {
        "ldp" => {
            let proof = vp
                .generate_proof(&key, &proof_options, resolver, &mut context_loader)
                .await
                .unwrap();
            vp.add_proof(proof);
            let result = vp
                .verify(Some(proof_options), resolver, &mut context_loader)
                .await;
            if !result.errors.is_empty() {
                panic!("verify failed: {:#?}", result);
            }
            let writer = std::io::BufWriter::new(std::io::stdout());
            serde_json::to_writer_pretty(writer, &vp).unwrap();
        }
        "jwt" => {
            proof_options.created = None;
            proof_options.checks = None;
            let jwt = vp
                .generate_jwt(Some(&key), &proof_options, resolver)
                .await
                .unwrap();
            print!("{}", jwt);
            let result =
                ssi::vc::Presentation::verify_jwt(&jwt, None, resolver, &mut context_loader).await;
            if !result.errors.is_empty() {
                panic!("verify failed: {:#?}", result);
            }
        }
        format => panic!("unknown output proof format: {}", format),
    }
}
