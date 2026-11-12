//! RFC 9901 Section 7.1: a verifier refuses a repeated digest (step 4) and a
//! disclosure named `_sd` or `...` (step 3).
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use ssi_sd_jwt::{RevealError, SdAlg, SdJwt};

fn b64(value: &Value) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
}

/// Builds a compact SD-JWT. The signature is a placeholder: revealing does
/// not verify it.
fn sd_jwt(payload: Value, disclosures: &[&str]) -> String {
    let mut s = format!(
        "{}.{}.c2ln",
        b64(&json!({"alg": "ES256", "typ": "dc+sd-jwt"})),
        b64(&payload)
    );
    for d in disclosures {
        s.push('~');
        s.push_str(d);
    }
    s.push('~');
    s
}

fn reveal(compact: &str) -> Result<(), RevealError> {
    SdJwt::new(compact).unwrap().decode_reveal_any().map(|_| ())
}

#[test]
fn a_decoy_digest_repeated_in_sd_is_refused() {
    let given_name = b64(&json!(["salt-1", "given_name", "Erika"]));
    let decoy = SdAlg::Sha256.hash("not a disclosure");
    let payload = json!({
        "_sd_alg": "sha-256",
        "_sd": [SdAlg::Sha256.hash(&given_name), decoy, decoy],
    });
    assert!(matches!(
        reveal(&sd_jwt(payload, &[&given_name])),
        Err(RevealError::RepeatedDigest(d)) if d == decoy
    ));
}

#[test]
fn a_decoy_digest_repeated_in_an_array_is_refused() {
    let decoy = SdAlg::Sha256.hash("not a disclosure");
    let payload = json!({
        "_sd_alg": "sha-256",
        "nationalities": [{"...": decoy}, {"...": decoy}],
    });
    assert!(matches!(
        reveal(&sd_jwt(payload, &[])),
        Err(RevealError::RepeatedDigest(_))
    ));
}

#[test]
fn a_disclosure_named_sd_is_refused() {
    let disclosure = b64(&json!(["salt-1", "_sd", ["x"]]));
    let payload = json!({
        "_sd_alg": "sha-256",
        "_sd": [SdAlg::Sha256.hash(&disclosure)],
    });
    assert!(matches!(
        reveal(&sd_jwt(payload, &[&disclosure])),
        Err(RevealError::ReservedClaimName(name)) if name == "_sd"
    ));
}

#[test]
fn a_disclosure_named_ellipsis_is_refused() {
    let disclosure = b64(&json!(["salt-1", "...", "x"]));
    let payload = json!({
        "_sd_alg": "sha-256",
        "_sd": [SdAlg::Sha256.hash(&disclosure)],
    });
    assert!(matches!(
        reveal(&sd_jwt(payload, &[&disclosure])),
        Err(RevealError::ReservedClaimName(name)) if name == "..."
    ));
}

#[test]
fn distinct_digests_still_reveal() {
    let given_name = b64(&json!(["salt-1", "given_name", "Erika"]));
    let payload = json!({
        "_sd_alg": "sha-256",
        "_sd": [
            SdAlg::Sha256.hash(&given_name),
            SdAlg::Sha256.hash("decoy one"),
            SdAlg::Sha256.hash("decoy two"),
        ],
    });
    assert!(reveal(&sd_jwt(payload, &[&given_name])).is_ok());
}
