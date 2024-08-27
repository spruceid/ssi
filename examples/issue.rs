// To generate test vectors:
// cargo run --example issue ldp > examples/files/vc.jsonld
// cargo run --example issue jwt > examples/files/vc.jwt

use serde_json::json;
use ssi_claims::{
    data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
    jws::JwsPayload,
    vc::v1::ToJwtClaims,
    VerificationParameters,
};
use ssi_dids::DIDResolver;
use ssi_verification_methods::SingleSecretSigner;
use static_iref::iri;

async fn issue(proof_format: &str) {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    let mut key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    key.key_id = Some("did:example:foo#key1".to_string());
    let resolver = ssi::dids::example::ExampleDIDResolver::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(&resolver);
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    let vc: ssi::claims::vc::v1::SpecializedJsonCredential = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": ssi::xsd::DateTime::now(),
        "credentialSubject": {
            "id": uuid::Uuid::new_v4().urn().to_string()
        }
    }))
    .unwrap();

    let verification_method = iri!("did:example:foo#key1").into();

    match proof_format {
        "ldp" => {
            let options =
                ProofOptions::from_method_and_options(verification_method, Default::default());

            let suite = AnySuite::pick(&key, options.verification_method.as_ref()).unwrap();
            let vc = suite.sign(vc, &resolver, &signer, options).await.unwrap();

            let result = vc.verify(params).await.expect("verification failed");
            if let Err(e) = result {
                panic!("verify failed: {e}");
            }

            let stdout_writer = std::io::BufWriter::new(std::io::stdout());
            serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();
        }
        "jwt" => {
            let jwt = vc.to_jwt_claims().unwrap().sign(&key).await.unwrap();

            let result = jwt.verify(params).await.expect("verification failed");
            if let Err(e) = result {
                panic!("verify failed: {e}");
            }

            print!("{}", jwt);
        }
        format => panic!("unknown proof format: {}", format),
    }
}

#[async_std::main]
async fn main() {
    let proof_format = std::env::args().nth(1);
    issue(&proof_format.unwrap()[..]).await;
}

#[cfg(test)]
mod test {
    use super::*;

    #[async_std::test]
    async fn ldp() {
        issue("ldp").await;
    }

    #[async_std::test]
    async fn jwt() {
        issue("jwt").await;
    }
}
