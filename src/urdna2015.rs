use std::collections::BTreeMap as Map;
use std::collections::HashSet;

use crate::error::Error;
use crate::hash::sha256;
use crate::rdf::{BlankNodeLabel, DataSet, Predicate, Statement};

/// https://json-ld.github.io/normalization/spec/#normalization-state
#[derive(Debug, Clone)]
pub struct NormalizationState<'a> {
    pub blank_node_to_quads: Map<&'a str, Vec<&'a Statement>>,
    pub hash_to_blank_nodes: Map<String, Vec<&'a str>>,
    pub canonical_issuer: IdentifierIssuer,
}

/// https://json-ld.github.io/normalization/spec/#dfn-identifier-issuer
/// https://json-ld.github.io/normalization/spec/#blank-node-identifier-issuer-state
#[derive(Debug, Clone)]
pub struct IdentifierIssuer {
    pub identifier_prefix: String,
    pub identifier_counter: u64,
    pub issued_identifiers_list: Vec<(String, String)>,
}

impl IdentifierIssuer {
    pub fn new(prefix: String) -> Self {
        Self {
            identifier_prefix: prefix,
            identifier_counter: 0,
            issued_identifiers_list: Vec::new(),
        }
    }
    pub fn find_issued_identifier(&self, existing_identifier: &str) -> Option<&str> {
        // TODO(optimize): index issued_identifiers_list by existing_identifier
        self.issued_identifiers_list
            .iter()
            .find(|(_, existing_id)| existing_id == existing_identifier)
            .map(|(issued_identifier, _)| issued_identifier.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct HashNDegreeQuadsOutput {
    pub hash: String,
    pub issuer: IdentifierIssuer,
}

fn digest_to_lowerhex(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

/// https://json-ld.github.io/normalization/spec/#hash-first-degree-quads
pub fn hash_first_degree_quads(
    normalization_state: &mut NormalizationState,
    reference_blank_node_identifier: &str,
) -> Result<String, Error> {
    // https://json-ld.github.io/normalization/spec/#algorithm-1
    // 1
    let mut nquads: Vec<String> = Vec::new();
    // 2
    if let Some(quads) = normalization_state
        .blank_node_to_quads
        .get(reference_blank_node_identifier)
    {
        // 3
        for quad in quads {
            // 3.1
            let mut quad: Statement = (*quad).clone();
            // 3.1.1
            for label in quad.blank_node_components_mut() {
                // 3.1.1.1
                label.0 = if label.0 == reference_blank_node_identifier {
                    "_:a".to_string()
                } else {
                    "_:z".to_string()
                };
            }
            let nquad = String::from(&quad);
            nquads.push(nquad);
        }
    }
    // 4
    nquads.sort();
    // 5
    let joined_nquads = nquads.join("");
    let nquads_digest = sha256(joined_nquads.as_bytes())?;
    let hash_hex = digest_to_lowerhex(&nquads_digest);
    Ok(hash_hex)
}

/// https://json-ld.github.io/normalization/spec/
pub fn normalize(input_dataset: &DataSet) -> Result<DataSet, Error> {
    // https://json-ld.github.io/normalization/spec/#algorithm
    // 1
    let mut normalization_state = NormalizationState {
        blank_node_to_quads: Map::new(),
        hash_to_blank_nodes: Map::new(),
        canonical_issuer: IdentifierIssuer::new("_:c14n".to_string()),
    };
    // 2
    let input_dataset_quads = input_dataset.statements();
    for quad in input_dataset_quads.iter() {
        // 2.1
        for blank_node_identifier in quad.blank_node_components() {
            normalization_state
                .blank_node_to_quads
                .entry(&blank_node_identifier.0)
                .or_insert_with(Vec::new)
                .push(&quad);
        }
    }
    // 3
    let mut non_normalized_identifiers: HashSet<&str> = normalization_state
        .blank_node_to_quads
        .keys()
        .cloned()
        .collect();
    // 4
    let mut simple = true;
    // 5
    while simple {
        // 5.1
        simple = false;
        // 5.2
        normalization_state.hash_to_blank_nodes.clear();
        // 5.3
        for identifier in non_normalized_identifiers.iter() {
            // 5.3.1
            let hash = hash_first_degree_quads(&mut normalization_state, identifier)?;
            // 5.3.2
            normalization_state
                .hash_to_blank_nodes
                .entry(hash)
                .or_insert_with(Vec::new)
                .push(identifier);
        }
        // 5.4
        let mut hashes_to_remove = Vec::new();
        for (hash, identifier_list) in normalization_state.hash_to_blank_nodes.iter() {
            // 5.4.1
            if identifier_list.len() > 1 {
                continue;
            }
            // 5.4.2
            let identifier = match identifier_list.iter().next() {
                Some(id) => id,
                None => continue,
            };
            // note: canonical issuer is not passed
            issue_identifier(&mut normalization_state.canonical_issuer, &identifier)?;
            // 5.4.3
            non_normalized_identifiers.remove(identifier);
            // 5.4.4
            // Cannot remove while iterating
            hashes_to_remove.push(hash.clone());
            // 5.4.5
            simple = true;
        }
        for hash in hashes_to_remove {
            normalization_state.hash_to_blank_nodes.remove(&hash);
        }
        // 6
        // Clone normalization_state to avoid mutable borrow
        for (_hash, identifier_list) in normalization_state.hash_to_blank_nodes.clone() {
            // 6.1
            let mut hash_path_list: Vec<HashNDegreeQuadsOutput> = Vec::new();
            // 6.2
            for identifier in identifier_list {
                // 6.2.1
                if normalization_state
                    .canonical_issuer
                    .find_issued_identifier(identifier)
                    .is_some()
                {
                    continue;
                }
                // 6.2.2
                let mut temporary_issuer = IdentifierIssuer::new("_:b".to_string());
                // 6.2.3
                issue_identifier(&mut temporary_issuer, identifier)?;
                // 6.2.4
                hash_path_list.push(hash_n_degree_quads(
                    &mut normalization_state,
                    identifier,
                    &mut temporary_issuer,
                )?);
            }
            // 6.3
            hash_path_list.sort_by(|a, b| a.hash.cmp(&b.hash));
            for result in hash_path_list {
                // 6.3.1
                let identifier_issuer = result.issuer;
                for (_, existing_identifier) in identifier_issuer.issued_identifiers_list {
                    issue_identifier(
                        &mut normalization_state.canonical_issuer,
                        &existing_identifier,
                    )?;
                }
            }
        }
    }
    // 7
    let mut normalized_dataset = DataSet::default();
    for quad in input_dataset_quads.iter() {
        // 7.1
        let mut quad_copy = quad.clone();
        for label in quad_copy.blank_node_components_mut() {
            let canonical_identifier = match normalization_state
                .canonical_issuer
                .find_issued_identifier(&label.0)
            {
                Some(id) => id,
                None => return Err(Error::MissingIdentifier),
            };
            label.0 = canonical_identifier.to_string();
        }
        // 7.2
        normalized_dataset.add_statement(quad_copy);
    }
    // 8
    Ok(normalized_dataset)
}

/// https://json-ld.github.io/normalization/spec/#issue-identifier-algorithm
pub fn issue_identifier(
    identifier_issuer: &mut IdentifierIssuer,
    existing_identifier: &str,
) -> Result<String, Error> {
    // https://json-ld.github.io/normalization/spec/#algorithm-0
    // 1
    if let Some(id) = identifier_issuer.find_issued_identifier(existing_identifier) {
        return Ok(id.to_string());
    }
    // 2
    let issued_identifier = identifier_issuer.identifier_prefix.to_owned()
        + &identifier_issuer.identifier_counter.to_string();
    // 3
    identifier_issuer.issued_identifiers_list.push((
        issued_identifier.to_string(),
        existing_identifier.to_string(),
    ));
    // 4
    identifier_issuer.identifier_counter += 1;
    // 5
    Ok(issued_identifier)
}

/// https://json-ld.github.io/normalization/spec/#hash-n-degree-quads
pub fn hash_n_degree_quads(
    normalization_state: &mut NormalizationState,
    identifier: &str,
    issuer: &mut IdentifierIssuer,
) -> Result<HashNDegreeQuadsOutput, Error> {
    let mut issuer = issuer;
    // https://json-ld.github.io/normalization/spec/#algorithm-3
    let mut issuer_tmp: IdentifierIssuer;
    // 1
    let mut hash_to_related_blank_nodes: Map<String, Vec<&BlankNodeLabel>> = Map::new();
    // 2
    if let Some(quads) = normalization_state
        .blank_node_to_quads
        .get(identifier)
        // Clone to prevent multiple mutable borrows of normalization state
        .cloned()
    {
        // 3
        for quad in quads {
            // 3.1
            for (component, position) in quad.blank_node_components_with_position() {
                // Not checking for predicate since that cannot be a blank node identifier anyway
                if component.0 != identifier {
                    // 3.1.1
                    let hash = hash_related_blank_node(
                        normalization_state,
                        &component.0,
                        quad,
                        issuer,
                        position,
                    )?;
                    // 3.1.2
                    hash_to_related_blank_nodes
                        .entry(hash)
                        .or_insert_with(Vec::new)
                        .push(&component);
                }
            }
        }
    }
    // 4
    let mut data_to_hash = String::new();
    // 5
    // Using BTreeMap for sort by hash
    for (related_hash, blank_node_list) in hash_to_related_blank_nodes {
        // 5.1
        data_to_hash.push_str(&related_hash);
        // 5.2
        let mut chosen_path = String::new();
        // 5.3
        let mut chosen_issuer = None;
        // 5.4
        for permutation in permute::permutations_of(&blank_node_list) {
            // 5.4.1
            let mut issuer_copy = issuer.clone();
            // 5.4.2
            let mut path = String::new();
            // 5.4.3
            let mut recursion_list: Vec<String> = Vec::new();
            // 5.4.4
            for related in permutation {
                // 5.4.4.1
                if let Some(canonical_identifier) = normalization_state
                    .canonical_issuer
                    .find_issued_identifier(&related.0)
                    .as_ref()
                {
                    recursion_list.push(canonical_identifier.to_string());
                // 5.4.4.2
                } else {
                    // 5.4.4.2.1
                    if issuer_copy.find_issued_identifier(&related.0).is_none() {
                        recursion_list.push(related.0.to_string());
                    }
                    // 5.4.4.2.2
                    path += &issue_identifier(&mut issuer_copy, &related.0)?;
                }
                // 5.4.4.3
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue;
                }
            }
            // 5.4.5
            for related in recursion_list {
                // 5.4.5.1
                let result = hash_n_degree_quads(normalization_state, &related, &mut issuer_copy)?;
                // 5.4.5.2
                path.push_str(&issue_identifier(&mut issuer_copy, &related)?);
                // 5.4.5.3
                path.push('<');
                path.push_str(&result.hash);
                path.push('>');
                // 5.4.5.4
                issuer_copy = result.issuer;
                // 5.4.5.5
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue;
                }
            }
            // 5.4.6
            if chosen_path.is_empty() || path < chosen_path {
                chosen_path = path;
                chosen_issuer.replace(issuer_copy);
            }
        }
        // 5.5
        data_to_hash.push_str(&chosen_path);
        // 5.6
        issuer_tmp = match chosen_issuer {
            Some(issuer) => issuer,
            None => return Err(Error::MissingChosenIssuer),
        };
        issuer = &mut issuer_tmp;
    }
    // 6
    let digest = sha256(data_to_hash.as_bytes())?;
    let hash = digest_to_lowerhex(&digest);
    Ok(HashNDegreeQuadsOutput {
        hash,
        issuer: issuer.to_owned(),
    })
}

/// https://json-ld.github.io/normalization/spec/#hash-related-blank-node
pub fn hash_related_blank_node(
    normalization_state: &mut NormalizationState,
    related: &str,
    quad: &Statement,
    issuer: &mut IdentifierIssuer,
    position: char,
) -> Result<String, Error> {
    // https://json-ld.github.io/normalization/spec/#algorithm-2
    // 1
    let identifier = match normalization_state
        .canonical_issuer
        .find_issued_identifier(related)
    {
        Some(id) => id.to_string(),
        None => match issuer.find_issued_identifier(related) {
            Some(id) => id.to_string(),
            None => hash_first_degree_quads(normalization_state, related)?,
        },
    };
    // 2
    let mut input = position.to_string();
    // 3
    if position != 'g' {
        let Predicate::IRIRef(ref predicate) = quad.predicate;
        input.push('<');
        input.push_str(&predicate.0);
        input.push('>');
    }
    // 4
    input += &identifier;
    // 5
    let digest = sha256(input.as_bytes())?;
    let hash_hex = digest_to_lowerhex(&digest);
    Ok(hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// https://json-ld.github.io/normalization/tests/
    fn normalization_test_suite() {
        use std::fs::{self};
        use std::path::PathBuf;
        use std::str::FromStr;
        let case = std::env::args().skip(2).next();
        // Example usage to run a single test case:
        //   cargo test normalization_test_suite -- test022
        let mut passed = 0;
        let mut total = 0;
        for entry in fs::read_dir("json-ld-normalization/tests").unwrap() {
            let entry = entry.unwrap();
            let filename = entry.file_name().into_string().unwrap();
            if !filename.starts_with("test") || !filename.ends_with("-urdna2015.nq") {
                continue;
            }
            let num = &filename[0..7].to_string();
            if let Some(ref case) = case {
                if case != num {
                    continue;
                }
            }
            total += 1;
            let mut path = entry.path();
            let expected_str = fs::read_to_string(&path).unwrap();
            let in_file_name = num.to_string() + "-in.nq";
            path.set_file_name(PathBuf::from(in_file_name));
            let in_str = fs::read_to_string(&path).unwrap();
            let dataset = DataSet::from_str(&in_str).unwrap();
            let dataset_normalized = normalize(&dataset).unwrap();
            let normalized = dataset_normalized.to_nquads().unwrap();
            if &normalized == &expected_str {
                passed += 1;
            } else {
                let changes = difference::Changeset::new(&normalized, &expected_str, "\n");
                eprintln!("test {}: failed. diff:\n{}", num, changes);
            }
        }
        assert!(total > 0);
        assert_eq!(passed, total);
    }
}
