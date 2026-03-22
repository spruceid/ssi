use ssi::prelude::*;

#[async_std::test]
async fn verify_vc() {
    // Read the VC from a file path (configurable via VC_PATH env var)
    let vc_path = std::env::var("VC_PATH")
        .unwrap_or_else(|_| "verifiable_credential.json".to_string());

    let vc_json = std::fs::read_to_string(&vc_path)
        .unwrap_or_else(|e| panic!("failed to read VC from {vc_path}: {e}\nRun the issue test first: cargo test --test issue"));

    // Deserialize the signed VC
    let vc: AnyDataIntegrity<AnyJsonCredential> =
        serde_json::from_str(&vc_json).expect("failed to parse VC JSON");

    // With DID:JWK, the issuer's public key is embedded in the DID itself.
    // The resolver extracts it automatically — no separate key file needed.
    let vm_resolver = DIDJWK.into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    // Verify the VC signature
    vc.verify(params)
        .await
        .expect("verification error")
        .unwrap();

    println!("VC from {vc_path} verified successfully!");
}
