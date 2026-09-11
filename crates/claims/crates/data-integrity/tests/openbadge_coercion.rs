//! Context-coerced literal datatypes (OpenBadge).
//!
//! The OpenBadge v3 context coerces `hashed` to
//! `https://www.w3.org/2001/XMLSchema#boolean` (`https`, not the canonical
//! `http`), and the issuer signs over that quad. Canonicalization must keep
//! the coerced datatype in both the standard and the selective-disclosure
//! paths, or the signature does not verify.
//!
//! Both fixtures were issued by a throwaway test signer over synthetic data;
//! its Multikey is supplied inline so the tests run offline.
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

const ISSUER_DID: &str = "did:web:davis-index-precious-complimentary.trycloudflare.com:signer:test";
const ISSUER_VM: &str = "did:web:davis-index-precious-complimentary.trycloudflare.com:signer:test#e1c5161e-d7bf-4687-9436-7645b7ffe187";

/// Static resolver mapping the issuer's `did:web` verification method to its
/// Multikey, so the tests run offline (no DID resolution over the network).
fn issuer_resolver() -> HashMap<IriBuf, AnyMethod> {
    let vm: AnyMethod = parse(&format!(
        r#"{{
            "id": "{ISSUER_VM}",
            "type": "Multikey",
            "controller": "{ISSUER_DID}",
            "publicKeyMultibase": "zDnaexKarbL5kCjrurZPcLYxpGHQU7mbW4EK99UUyr2DPX1G3"
        }}"#
    ));
    HashMap::from([(ISSUER_VM.parse().unwrap(), vm)])
}

/// Standard path: an `ecdsa-rdfc-2019` OpenBadge credential verifies.
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

/// SD path: an OpenBadge credential with an `ecdsa-sd-2023` base proof (plus an
/// `ecdsa-rdfc-2019` signature) full-reveal-derives and verifies.
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
