//! This example shows how to parse a verifiable credential.
use std::fs;

use ssi_claims::{data_integrity::AnyDataIntegrity, vc::AnyJsonCredential};

#[async_std::main]
async fn main() {
    // Load the credential textual representation from the file system.
    let credential_content = fs::read_to_string("examples/files/vc.jsonld").unwrap();

    // Parse the credential into a JSON VC with any Data-Integrity proof.
    let vc: AnyDataIntegrity<AnyJsonCredential> =
        serde_json::from_str(&credential_content).unwrap();

    println!("{}", serde_json::to_string_pretty(&vc).unwrap());

    // The above can be done with the following helper function.
    let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(&credential_content)
        .unwrap();

    // Print the same credential.
    println!("{}", serde_json::to_string_pretty(&vc).unwrap());
}
