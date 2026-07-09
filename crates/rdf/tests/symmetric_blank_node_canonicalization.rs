//! Regression test for URDNA2015 (RDFC-1.0) canonical labeling of symmetric /
//! duplicate blank-node structures.
//!
//! `hash_n_degree_quads` step 5.4.4.1 (W3C rdf-canon §4.8, Hash N-Degree Quads)
//! must, when a `related` blank node already has a CANONICAL identifier, append
//! that identifier directly to the path. A prior implementation instead pushed
//! it onto the recursion list, which re-issued a fresh temporary identifier in
//! step 5.4.5 and corrupted the path — producing divergent canonical labels for
//! graphs containing many identical sub-structures (e.g. repeated `@list`s).
//!
//! The fixture is the jsonld.js reference canonical form of a real OpenBadge
//! credential carrying 18 identical `allowedValue` lists (its issuer proof
//! failed to verify before the fix). A correct, idempotent canonicalizer must
//! re-label its OWN canonical output to exactly the same labels.

use locspan::Meta;
use nquads_syntax::Parse;
use ssi_rdf::{urdna2015::normalize, LexicalQuad};

const CREDENTIAL3_CANONICAL: &str = include_str!("fixtures/openbadge-credential3-canonical.nq");

fn parse_nquads(src: &str) -> Vec<LexicalQuad> {
    nquads_syntax::Document::parse_str(src)
        .expect("valid n-quads")
        .0
        .into_iter()
        .map(Meta::into_value)
        .map(nquads_syntax::strip_quad)
        .collect()
}

fn sorted_lines(s: &str) -> Vec<&str> {
    let mut v: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
    v.sort_unstable();
    v
}

/// Canonicalizing an already-canonical dataset of symmetric blank nodes must be
/// idempotent. Before the step 5.4.4.1 fix this re-labeled the symmetric list
/// nodes differently (17 `rdf:rest` quads diverged), so re-canonicalization was
/// NOT idempotent.
#[test]
fn symmetric_lists_canonicalization_is_idempotent() {
    let quads = parse_nquads(CREDENTIAL3_CANONICAL);
    let out = normalize(quads.iter().map(LexicalQuad::as_lexical_quad_ref)).into_nquads();

    let got = sorted_lines(&out);
    let expected = sorted_lines(CREDENTIAL3_CANONICAL);
    assert_eq!(
        got, expected,
        "URDNA2015 must be idempotent on symmetric blank-node structures \
         (see hash_n_degree_quads step 5.4.4.1)"
    );
}
