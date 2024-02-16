//! This example shows how to verify a Data-Integrity Verifiable Credential.
use std::fs;

use ssi_dids::{DIDVerifier, StaticDIDResolver};

#[async_std::main]
async fn main() {
    // Load the credential textual representation from the file system.
    let credential_content = fs::read_to_string("examples/files/vc.jsonld").unwrap();

    // All of the above can be done with the following helper function.
    let vc = ssi::claims::data_integrity::any_credential_from_json_str(&credential_content)
        .await
        .unwrap();

    // Prepare our verifier.
    let verifier = create_verifier();

    // Verify the VC!
    assert!(vc.verify(&verifier).await.unwrap().is_valid());
    println!("Success!")
}

fn create_verifier() -> DIDVerifier<StaticDIDResolver> {
    // Create a static DID resolver that resolves `did:example:foo` into a
    // static DID document.
    let mut did_resolver = ssi::dids::StaticDIDResolver::new();
    did_resolver.insert(
        "did:example:foo".parse().unwrap(),
        ssi::dids::resolution::Output::from_content(
            include_bytes!("../crates/dids/core/tests/vectors/did-example-foo.json").to_vec(),
            Some("application/did+json".to_owned()),
        ),
    );

    // Turn the DID resolver into a verifier.
    DIDVerifier::new(did_resolver)
}