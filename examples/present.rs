// To generate test vectors:
// cargo run --example present ldp ldp < examples/files/vc.jsonld > examples/files/vp.jsonld
// cargo run --example present ldp jwt < examples/files/vc.jsonld > examples/files/vp.jwt
// cargo run --example present jwt ldp < examples/files/vc.jwt > examples/files/vp-jwtvc.jsonld
// cargo run --example present jwt jwt < examples/files/vc.jwt > examples/files/vp-jwtvc.jwt
//
// For `nushell` users:
// cat examples/files/vc.jsonld | cargo run --example present ldp ldp | save examples/files/vp.jsonld
// cat examples/files/vc.jsonld | cargo run --example present ldp jwt | save examples/files/vp.jwt
// cat examples/files/vc.jwt | cargo run --example present jwt ldp | save examples/files/vp-jwtvc.jsonld
// cat examples/files/vc.jwt | cargo run --example present jwt jwt | save examples/files/vp-jwtvc.jwt
use ssi::{
    claims::{
        data_integrity::{AnyInputContext, AnySuite, CryptographicSuiteInput, ProofConfiguration},
        jws::CompactJWSString,
        vc::JsonVerifiableCredential,
    },
    dids::DIDVerifier,
    verification_methods::{signer::SingleSecretSigner, AnyJwkMethod, ProofPurpose},
};
use static_iref::{iri, uri};

#[async_std::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let proof_format_in = args.next().unwrap();
    let proof_format_out = args.next().unwrap();

    let key_str = include_str!("../tests/ed25519-2020-10-18.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = DIDVerifier::new(ssi::dids::example::ExampleDIDResolver::default());
    let signer = SingleSecretSigner::new(key.clone());

    let mut reader = std::io::BufReader::new(std::io::stdin());
    let vc = match &proof_format_in[..] {
        "ldp" => {
            let vc_ldp: JsonVerifiableCredential = serde_json::from_reader(reader).unwrap();
            ssi::claims::JsonCredentialOrJws::Credential(vc_ldp)
        }
        "jwt" => {
            use std::io::Read;
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer).unwrap();

            match CompactJWSString::new(buffer) {
                Ok(vc_jwt) => ssi::claims::JsonCredentialOrJws::Jws(vc_jwt),
                Err(_) => {
                    panic!("Input must be a compact JWT");
                }
            }
        }
        format => panic!("unknown input proof format: {}", format),
    };

    let vp = ssi::claims::vc::JsonPresentation::new(
        None,
        vec![uri!("did:example:foo").to_owned()],
        vec![vc],
    );

    // let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    // let verification_method = "did:example:foo#key2".to_string();
    // proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    // proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    // proof_options.challenge = Some("example".to_string());
    let verification_method = iri!("did:example:foo#key2").into();

    match &proof_format_out[..] {
        "ldp" => {
            let mut params = ProofConfiguration::from_method(verification_method);

            params.proof_purpose = ProofPurpose::Authentication;
            params.challenge = Some("example".to_owned());

            let suite = AnySuite::pick(&key, Some(&params.verification_method)).unwrap();
            let vp = suite
                .sign(vp, AnyInputContext::default(), &resolver, &signer, params)
                .await
                .unwrap();

            let result = vp.verify(&resolver).await.expect("verification failed");
            if !result.is_valid() {
                panic!("verify failed");
            }

            let writer = std::io::BufWriter::new(std::io::stdout());
            serde_json::to_writer_pretty(writer, &vp).unwrap();
        }
        "jwt" => {
            let jwt = vp
                .to_jwt_claims()
                .unwrap()
                .sign(
                    key.get_algorithm().unwrap(),
                    &verification_method,
                    &resolver,
                    &signer,
                )
                .await
                .unwrap();

            if !jwt.verify::<AnyJwkMethod>(&resolver).await.unwrap() {
                panic!("verify failed");
            }

            print!("{}", jwt);
        }
        format => panic!("unknown output proof format: {}", format),
    }
}
