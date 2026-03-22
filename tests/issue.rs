use serde::{Deserialize, Serialize};
use ssi::claims::vc::syntax::NonEmptyVec;
use ssi::claims::vc::v1::JsonCredential;
use ssi::prelude::*;
use static_iref::uri;

#[derive(Serialize, Deserialize)]
struct CredentialSubject {
    #[serde(rename = "https://example.org/#name")]
    name: String,
    #[serde(rename = "https://example.org/#email")]
    email: String,
}

#[async_std::test]
async fn issue_vc() {
    // Load the issuer's key from file, or generate a new one and save it.
    // Persisting the key lets the issuer reuse the same DID across issuances.
    let key_path = std::env::var("ISSUER_KEY_PATH")
        .unwrap_or_else(|_| "issuer_key.jwk".to_string());

    let key: JWK = match std::fs::read_to_string(&key_path) {
        Ok(contents) => {
            println!("Loaded issuer key from {key_path}");
            serde_json::from_str(&contents).expect("failed to parse issuer key")
        }
        Err(_) => {
            let new_key = JWK::generate_p256();
            let key_json = serde_json::to_string_pretty(&new_key)
                .expect("failed to serialize key");
            std::fs::write(&key_path, &key_json).expect("failed to save issuer key");
            println!("Generated new issuer key and saved to {key_path}");
            new_key
        }
    };

    // Create a DID from the public key
    let did = DIDJWK::generate_url(&key.to_public());

    // Create the credential
    let credential = JsonCredential::<CredentialSubject>::new(
        Some(uri!("https://example.org/#CredentialId").to_owned()),
        did.as_uri().to_owned().into(), // issuer = the DID
        DateTime::now().into(),
        NonEmptyVec::new(CredentialSubject {
            name: "Alice Doe".to_string(),
            email: "alice.doe@example.com".to_string(),
        }),
    );

    // Set up resolver, signer, and verification method
    let vm_resolver = DIDJWK.into_vm_resolver();
    let signer = SingleSecretSigner::new(key.clone()).into_local();
    let verification_method = did.into_iri().into();

    // Pick a cryptosuite and sign the credential
    let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
        .expect("could not find appropriate cryptosuite");

    let vc = cryptosuite
        .sign(
            credential,
            &vm_resolver,
            &signer,
            ProofOptions::from_method(verification_method),
        )
        .await
        .expect("signature failed");

    // Save the signed VC to a JSON file
    let vc_path = std::env::var("VC_PATH")
        .unwrap_or_else(|_| "verifiable_credential.json".to_string());
    let json = serde_json::to_string_pretty(&vc).expect("failed to serialize VC");
    std::fs::write(&vc_path, json).expect("failed to write VC file");

    println!("Verifiable Credential saved to {vc_path}");
}
