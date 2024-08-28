use base64::Engine;
use iref::Iri;
use rdf_types::{BlankId, BlankIdBuf, Id, LexicalQuad, LexicalQuadRef, Literal, Quad, Term};
use ssi_rdf::urdna2015::NormalizingSubstitution;
use std::collections::HashMap;

use crate::HmacShaAny;

pub fn create_hmac_id_label_map_function(
    hmac: &mut HmacShaAny,
) -> impl '_ + FnMut(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf> {
    move |canonical_map| {
        canonical_map
            .iter()
            .map(|(key, value)| {
                hmac.update(value.suffix().as_bytes());
                let digest = hmac.finalize_reset();
                let b64_url_digest = BlankIdBuf::new(format!(
                    "_:u{}",
                    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest)
                ))
                .unwrap();
                (key.clone(), b64_url_digest)
            })
            .collect()
    }
}

/// See: <https://www.w3.org/TR/vc-di-ecdsa/#createlabelmapfunction>
pub fn create_label_map_function(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
) -> impl '_ + Fn(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf> {
    |canonical_id_map| {
        let mut bnode_id_map = HashMap::new();

        for (key, value) in canonical_id_map {
            if let Some(new_label) = label_map.get(value) {
                bnode_id_map.insert(key.clone(), new_label.clone());
            }
        }

        bnode_id_map
    }
}

pub fn label_replacement_canonicalize_nquads(
    mut label_map_factory: impl FnMut(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf>,
    quads: &[LexicalQuad],
) -> (Vec<LexicalQuad>, HashMap<BlankIdBuf, BlankIdBuf>) {
    let quads_ref = quads.iter().map(LexicalQuad::as_lexical_quad_ref);
    let bnode_identifier_map = ssi_rdf::urdna2015::normalize(quads_ref).into_substitution();

    let label_map = label_map_factory(&bnode_identifier_map);

    let mut canonical_quads: Vec<_> = quads
        .iter()
        .map(|quad| relabel_quad(&label_map, quad.as_lexical_quad_ref()))
        .collect();
    canonical_quads.sort();
    canonical_quads.dedup();

    (canonical_quads, label_map)
}

pub fn relabel_quads(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    quads: &[LexicalQuad],
) -> Vec<LexicalQuad> {
    quads
        .iter()
        .map(|quad| relabel_quad(label_map, quad.as_lexical_quad_ref()))
        .collect()
}

fn relabel_quad(label_map: &HashMap<BlankIdBuf, BlankIdBuf>, quad: LexicalQuadRef) -> LexicalQuad {
    Quad(
        relabel_id(label_map, quad.0),
        quad.1.to_owned(),
        relabel_term(label_map, quad.2),
        quad.3.map(|g| relabel_id(label_map, g)),
    )
}

fn relabel_id(label_map: &HashMap<BlankIdBuf, BlankIdBuf>, id: Id<&Iri, &BlankId>) -> Id {
    match id {
        Id::Iri(i) => Id::Iri(i.to_owned()),
        Id::Blank(b) => Id::Blank(match label_map.get(b) {
            Some(c) => c.clone(),
            None => b.to_owned(),
        }),
    }
}

fn relabel_term(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    term: Term<Id<&Iri, &BlankId>, &Literal>,
) -> Term {
    match term {
        Term::Id(id) => Term::Id(relabel_id(label_map, id)),
        Term::Literal(l) => Term::Literal(l.clone()),
    }
}
