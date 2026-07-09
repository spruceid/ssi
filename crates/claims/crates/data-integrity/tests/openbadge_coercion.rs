//! Regression tests for context-coerced literal datatypes (OpenBadge).
//!
//! The OpenBadge v3 context coerces some properties to a NON-canonical XSD
//! namespace — e.g. `hashed` → `https://www.w3.org/2001/XMLSchema#boolean`
//! (`https`, not the canonical `http`). A conformant JSON-LD→RDF serializer
//! honors that coercion, and the issuer signs over the `https`-typed quad. ssi's
//! `linked_data::to_lexical_quads` path re-derived such literals from the native
//! Rust value and emitted the canonical `http` datatype instead, producing quads
//! that did not match what the issuer signed — so verification of these (valid)
//! credentials failed. The fix routes canonicalization through `to_rdf` (which
//! honors the coercion) in BOTH the selective-disclosure path and the standard
//! Data Integrity path.
//!
//! Both fixtures are real credentials issued by `did:web:ccp-pilot.cccdigitalcenter.org`;
//! the issuer key is supplied inline so the tests run fully offline.
#![cfg(all(feature = "w3c", feature = "secp256r1"))]

use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::Parse;
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::{AnyDataIntegrity, AnySelectionOptions};
use ssi_json_ld::ContextLoader;
use ssi_verification_methods::AnyMethod;

const SD_CREDENTIAL: &str = include_str!("openbadge_sd_credential.json");
const RDFC_CREDENTIAL: &str = include_str!("openbadge_rdfc_credential.json");
const OB_CONTEXT: &str = include_str!("contexts/openbadge-v3p0.jsonld");

fn parse<T: serde::de::DeserializeOwned>(src: &str) -> T {
    let json = json_syntax::Value::parse_str(src).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

/// Offline loader for the OpenBadge v3 context (the only `@context` the static
/// loader does not bundle).
fn ob_loader() -> ContextLoader {
    ContextLoader::default()
        .with_context_map_from(HashMap::from([(
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json".to_owned(),
            OB_CONTEXT.to_owned(),
        )]))
        .unwrap()
}

/// Static resolver mapping the issuer's `did:web` verification method to its
/// Multikey, so the tests run offline (no DID resolution over the network).
fn issuer_resolver() -> HashMap<IriBuf, AnyMethod> {
    let vm: AnyMethod = parse(
        r#"{
            "id": "did:web:ccp-pilot.cccdigitalcenter.org#vm-cacp-ic",
            "type": "Multikey",
            "controller": "did:web:ccp-pilot.cccdigitalcenter.org",
            "publicKeyMultibase": "zDnaeVG1VZSYsdqKZTK5zmR9ZN3TWxXGRV6oNZa7abMNJLMwe"
        }"#,
    );
    HashMap::from([(
        "did:web:ccp-pilot.cccdigitalcenter.org#vm-cacp-ic"
            .parse()
            .unwrap(),
        vm,
    )])
}

/// Standard Data Integrity path: an `ecdsa-rdfc-2019` OpenBadge credential whose
/// context coerces a boolean to a non-canonical (`https`) XSD datatype must
/// verify. Before the fix the recomputed claims hash used `http` and the
/// signature was rejected.
#[async_std::test]
async fn openbadge_rdfc_with_coerced_datatype_verifies() {
    let vc: AnyDataIntegrity = parse(RDFC_CREDENTIAL);
    let params =
        VerificationParameters::from_resolver(issuer_resolver()).with_json_ld_loader(ob_loader());
    let outcome = vc.verify(params).await.expect("verification ran");
    assert!(
        outcome.is_ok(),
        "OpenBadge ecdsa-rdfc-2019 credential with context-coerced datatypes must verify: {outcome:?}"
    );
}

/// Selective-disclosure path: an OpenBadge credential carrying an `ecdsa-sd-2023`
/// base proof (alongside an `ecdsa-rdfc-2019` full-document signature) must
/// full-reveal-derive AND verify, despite the coerced boolean datatype.
#[async_std::test]
async fn openbadge_sd_full_reveal_verifies() {
    let vc: AnyDataIntegrity = parse(SD_CREDENTIAL);
    let params =
        VerificationParameters::from_resolver(issuer_resolver()).with_json_ld_loader(ob_loader());
    let options: AnySelectionOptions = parse(r#"{ "selectivePointers": ["/credentialSubject"] }"#);

    let derived = vc
        .select(params, options)
        .await
        .expect("full-reveal derive must succeed");

    let derived_value = json_syntax::to_value(&derived).unwrap();
    let derived_vc: AnyDataIntegrity = json_syntax::from_value(derived_value).unwrap();
    let params =
        VerificationParameters::from_resolver(issuer_resolver()).with_json_ld_loader(ob_loader());
    let outcome = derived_vc.verify(params).await.expect("verification ran");
    assert!(
        outcome.is_ok(),
        "derived OpenBadge SD credential must verify against the issuer base proof: {outcome:?}"
    );
}
