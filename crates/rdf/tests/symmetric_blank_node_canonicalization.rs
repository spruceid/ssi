//! URDNA2015 (RDFC-1.0) labeling of symmetric / duplicate blank-node structures
//! (`hash_n_degree_quads` step 5.4.4.1).
//!
//! The fixture is the jsonld.js `canonize` output for
//! `fixtures/openbadge-credential3.json`, an OpenBadge credential with 20
//! identical `allowedValue` lists (byte-identical to ssi's own pipeline).
//! Re-canonicalizing it must yield the same labels.

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

/// Canonicalization must be idempotent on symmetric blank nodes. Recursing on
/// already-canonical identifiers relabels the list nodes.
#[test]
fn symmetric_lists_canonicalization_is_idempotent() {
    let quads = parse_nquads(CREDENTIAL3_CANONICAL);
    let out = normalize(quads.iter().map(LexicalQuad::as_lexical_quad_ref)).into_nquads();

    let got = sorted_lines(&out);
    let expected = sorted_lines(CREDENTIAL3_CANONICAL);
    assert_eq!(
        got, expected,
        "URDNA2015 must be idempotent on symmetric blank-node structures \
         (see hash_n_degree_quads §5.4.4.1)"
    );
}
