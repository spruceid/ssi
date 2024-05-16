//! This example shows how to parse a verifiable credential.
use std::fs;

use ssi_claims::{data_integrity::AnyDataIntegrity, JsonCredential};

#[async_std::main]
async fn main() {
    // Load the credential textual representation from the file system.
    let credential_content = fs::read_to_string("examples/files/vc.jsonld").unwrap();

    // Parse the credential into a JSON VC with any Data-Integrity proof.
    let credential: AnyDataIntegrity<JsonCredential> =
        serde_json::from_str(&credential_content).unwrap();

    // Separate the claims from the proofs and turn it into actually verifiable
    // claims.
    let vc = ssi::claims::Verifiable::new(credential).await.unwrap();

    // At this point the VC is ready to be verified.
    // We just print it instead in this example.
    println!("{}", serde_json::to_string_pretty(&vc).unwrap());

    // All of the above can be done with the following helper function.
    let vc = ssi::claims::vc::any_credential_from_json_str(&credential_content)
        .await
        .unwrap();

    // Print the same credential.
    println!("{}", serde_json::to_string_pretty(&vc).unwrap());
}
