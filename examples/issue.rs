// To generate test vectors:
// cargo run --example issue ldp > examples/files/vc.jsonld
// cargo run --example issue jwt > examples/files/vc.jwt

use serde_json::json;
use ssi_claims::{
    data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
    jws::JWSPayload,
    vc::v1::ToJwtClaims,
    VerifiableClaims,
};
use ssi_dids::DIDResolver;
use ssi_verification_methods::SingleSecretSigner;
use static_iref::iri;

#[async_std::main]
async fn main() {
    let key_str = include_str!("../tests/rsa2048-2020-08-25.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = ssi::dids::example::ExampleDIDResolver::default().with_default_options();
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    let vc: ssi::claims::vc::v1::SpecializedJsonCredential = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": ssi::xsd_types::DateTime::now(),
        "credentialSubject": {
            "id": uuid::Uuid::new_v4().to_urn().to_string()
        }
    }))
    .unwrap();

    let verification_method = iri!("did:example:foo#key1").into();

    let proof_format = std::env::args().nth(1);
    match &proof_format.unwrap()[..] {
        "ldp" => {
            let params =
                ProofOptions::from_method_and_options(verification_method, Default::default());

            let suite = AnySuite::pick(&key, params.verification_method.as_ref()).unwrap();
            let vc = suite.sign(vc, &resolver, &signer, params).await.unwrap();

            let result = vc.verify(&resolver).await.expect("verification failed");
            if !result.is_ok() {
                panic!("verify failed");
            }

            let stdout_writer = std::io::BufWriter::new(std::io::stdout());
            serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();
        }
        "jwt" => {
            let jwt = vc.to_jwt_claims().unwrap().sign(&key).await.unwrap();

            let result = jwt.verify(&resolver).await.expect("verification failed");
            if !result.is_ok() {
                panic!("verify failed");
            }

            print!("{}", jwt);
        }
        format => panic!("unknown proof format: {}", format),
    }
}
