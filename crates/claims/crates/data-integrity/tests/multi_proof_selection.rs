//! Regression test for selective disclosure over a multi-proof credential.
//!
//! The pilot issuer emits a proof *set*: `ecdsa-rdfc-2019` + `ecdsa-jcs-2019`
//! (full-document signatures) alongside an `ecdsa-sd-2023` base proof. Only the
//! SD base proof is derivation material — the full-document signatures cannot
//! survive selective disclosure. `DataIntegrity::select` must therefore derive
//! from the lone SD base proof and ignore its companions, rather than refusing
//! the whole set with `AmbiguousProof`.
//!
//! The fixture is the exact credential that triggered `SdDeriveFailed`
//! (AmbiguousProof) in the wallet.
#![cfg(all(feature = "w3c", feature = "secp256r1"))]

use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::Parse;
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::{AnyDataIntegrity, AnySelectionOptions};
use ssi_dids::{DIDKey, VerificationMethodDIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_verification_methods::AnyMethod;

const CREDENTIAL: &str = include_str!("multi_proof_credential.json");
const FIRST_RESPONDER: &str = include_str!("contexts/first-responder-v1.jsonld");
const RENDER_V2RC1: &str = include_str!("contexts/render-method-v2rc1.jsonld");
const RENDER_V2RC2: &str = include_str!("contexts/render-method-v2rc2.jsonld");

fn parse<T: serde::de::DeserializeOwned>(src: &str) -> T {
    let json = json_syntax::Value::parse_str(src).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

/// The credential's `@context`s that the static loader does not bundle.
/// (`https://www.w3.org/ns/credentials/v2` IS bundled.)
fn offline_loader() -> ContextLoader {
    ContextLoader::default()
        .with_context_map_from(HashMap::from([
            (
                "https://w3id.org/first-responder/v1".to_owned(),
                FIRST_RESPONDER.to_owned(),
            ),
            (
                "https://w3id.org/vc/render-method/v2rc1".to_owned(),
                RENDER_V2RC1.to_owned(),
            ),
            (
                "https://w3id.org/vc/render-method/v2rc2".to_owned(),
                RENDER_V2RC2.to_owned(),
            ),
        ]))
        .unwrap()
}

/// Cheap gate-only check: the lone `ecdsa-sd-2023` base proof is selected out of
/// the proof set instead of the whole set being refused as ambiguous. Runs
/// fully offline (no resolver / contexts needed — it asserts only the gate that
/// precedes any resolution).
#[async_std::test]
async fn select_over_proof_set_picks_sd_base() {
    let vc: AnyDataIntegrity = parse(CREDENTIAL);
    assert_eq!(
        vc.proofs.len(),
        3,
        "fixture should carry the rdfc + jcs + sd-2023 proof set"
    );

    let resolver: HashMap<IriBuf, AnyMethod> = HashMap::new();
    let params = VerificationParameters::from_resolver(resolver);
    let options: AnySelectionOptions = parse(r#"{ "selectivePointers": ["/credentialSubject"] }"#);

    let err = vc
        .select(params, options)
        .await
        .err()
        .expect("offline derivation cannot complete without contexts; we only assert the gate");

    // Pre-fix: `select` bailed at the proof-count gate with `AmbiguousProof`
    // before attempting anything.
    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains("AmbiguousProof"),
        "select must not refuse a multi-proof set as ambiguous; got: {rendered}"
    );
}

/// End-to-end: with the credential's contexts supplied offline and a real
/// did:key resolver, a full-subject-reveal derivation actually SUCCEEDS over the
/// 3-proof set, and the derived VC carries exactly the `ecdsa-sd-2023` derived
/// proof (the rdfc/jcs full-document signatures are dropped).
#[async_std::test]
async fn select_full_reveal_succeeds_over_proof_set() {
    let vc: AnyDataIntegrity = parse(CREDENTIAL);

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(DIDKey);
    let params =
        VerificationParameters::from_resolver(resolver).with_json_ld_loader(offline_loader());
    let options: AnySelectionOptions = parse(r#"{ "selectivePointers": ["/credentialSubject"] }"#);

    let derived = vc
        .select(params, options)
        .await
        .expect("full-reveal derive over the proof set must succeed");

    assert_eq!(
        derived.proofs.len(),
        1,
        "the derived VC keeps only the single derived SD proof"
    );
    let rendered = json_syntax::to_value(&derived).unwrap().to_string();
    assert!(
        rendered.contains("ecdsa-sd-2023"),
        "the surviving proof must be the ecdsa-sd-2023 derived proof"
    );
}

/// Full regression for the canonical-sort fix: the derived full-reveal credential
/// must actually VERIFY against the issuer's base proof.
///
/// This fixture mixes IRI-subject and blank-node-subject quads. Canonical
/// (RDFC-1.0) order is over the serialized N-Quad strings (IRIs sort before blank
/// nodes), but the label-replacement canonicalization previously sorted the
/// structural `LexicalQuad` (blank nodes before IRIs). The `mandatory_indexes`
/// stored at derive time then pointed at the wrong quads during verification, so
/// the recomputed `mandatory_hash` — and the base signature — did not match.
/// Asserting the derived proof verifies locks that in.
#[async_std::test]
async fn select_full_reveal_verifies_over_proof_set() {
    let vc: AnyDataIntegrity = parse(CREDENTIAL);

    let params = VerificationParameters::from_resolver(
        VerificationMethodDIDResolver::<_, AnyMethod>::new(DIDKey),
    )
    .with_json_ld_loader(offline_loader());
    let options: AnySelectionOptions = parse(r#"{ "selectivePointers": ["/credentialSubject"] }"#);

    let derived = vc
        .select(params, options)
        .await
        .expect("full-reveal derive over the proof set must succeed");

    // Re-parse the derived credential and verify its derived SD proof.
    let derived_value = json_syntax::to_value(&derived).unwrap();
    let derived_vc: AnyDataIntegrity = json_syntax::from_value(derived_value).unwrap();

    let params = VerificationParameters::from_resolver(
        VerificationMethodDIDResolver::<_, AnyMethod>::new(DIDKey),
    )
    .with_json_ld_loader(offline_loader());
    let outcome = derived_vc.verify(params).await.expect("verification ran");
    assert!(
        outcome.is_ok(),
        "derived full-reveal credential must verify against the issuer base proof: {outcome:?}"
    );
}
