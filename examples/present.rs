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
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        jws::{JwsPayload, JwsString},
    },
    verification_methods::{ProofPurpose, SingleSecretSigner},
};
use ssi_claims::{
    data_integrity::AnyDataIntegrity,
    vc::{v1::ToJwtClaims, AnyJsonCredential},
    VerificationParameters,
};
use ssi_dids::DIDResolver;
use static_iref::{iri, uri};

async fn verify(proof_format_in: &str, proof_format_out: &str, input_vc: &str) {
    let vc = match proof_format_in {
        "ldp" => {
            let vc_ldp: AnyDataIntegrity<AnyJsonCredential> =
                serde_json::from_str(input_vc).unwrap();
            ssi::claims::JsonCredentialOrJws::Credential(vc_ldp)
        }
        "jwt" => match JwsString::from_string(input_vc.to_string()) {
            Ok(vc_jwt) => ssi::claims::JsonCredentialOrJws::Jws(vc_jwt),
            Err(_) => {
                panic!("Input must be a compact JWT");
            }
        },
        format => panic!("unknown input proof format: {}", format),
    };

    let vp = ssi::claims::vc::v1::JsonPresentation::new(
        None,
        Some(uri!("did:example:foo").to_owned()),
        vec![vc],
    );

    let key_str = include_str!("../tests/ed25519-2020-10-18.json");
    let mut key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    key.key_id = Some("did:example:foo#key2".to_string());
    let resolver = ssi::dids::example::ExampleDIDResolver::default().into_vm_resolver();
    let verifier = VerificationParameters::from_resolver(&resolver);
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    // let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    // let verification_method = "did:example:foo#key2".to_string();
    // proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    // proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    // proof_options.challenge = Some("example".to_string());
    let verification_method = iri!("did:example:foo#key2").into();

    match proof_format_out {
        "ldp" => {
            let mut params = ProofOptions::from_method(verification_method);

            params.proof_purpose = ProofPurpose::Authentication;
            params.challenge = Some("example".to_owned());

            let suite = AnySuite::pick(&key, params.verification_method.as_ref()).unwrap();
            let vp = suite.sign(vp, &resolver, &signer, params).await.unwrap();

            let result = vp.verify(verifier).await.expect("verification failed");
            if result.is_err() {
                panic!("verify failed");
            }

            let writer = std::io::BufWriter::new(std::io::stdout());
            serde_json::to_writer_pretty(writer, &vp).unwrap();
        }
        "jwt" => {
            let jwt = vp.to_jwt_claims().unwrap().sign(&key).await.unwrap();

            let result = jwt.verify(verifier).await.expect("verification failed");
            if result.is_err() {
                panic!("verify failed");
            }

            print!("{}", jwt);
        }
        format => panic!("unknown output proof format: {}", format),
    }
}

#[async_std::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let proof_format_in = args.next().unwrap();
    let proof_format_out = args.next().unwrap();

    let input_vc = std::io::read_to_string(std::io::stdin()).unwrap();
    verify(&proof_format_in[..], &proof_format_out[..], &input_vc).await;
}

#[cfg(test)]
mod test {
    use super::*;

    #[async_std::test]
    async fn ldp_ldp() {
        verify("ldp", "ldp", include_str!("files/vc.jsonld")).await;
    }

    #[async_std::test]
    async fn ldp_jwt() {
        verify("ldp", "jwt", include_str!("files/vc.jsonld")).await;
    }

    #[async_std::test]
    async fn jwt_ldp() {
        verify("jwt", "ldp", include_str!("files/vc.jwt")).await;
    }

    #[async_std::test]
    async fn jwt_jwt() {
        verify("jwt", "jwt", include_str!("files/vc.jwt")).await;
    }
}
