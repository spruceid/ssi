use k256::sha2::{Digest, Sha256};
use rdf_types::LexicalQuad;
use ssi_bbs::proof_verify;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_data_integrity_core::{suite::standard::VerificationAlgorithm, ProofRef};
use ssi_di_sd_primitives::canonicalize::{create_label_map_function, relabel_quads};
use ssi_rdf::{urdna2015::NormalizingSubstitution, IntoNQuads};
use ssi_verification_methods::{multikey::DecodedMultikey, Multikey};

use crate::Bbs2023;

use super::{Bbs2023SignatureAlgorithm, DerivedFeatureOption, HashData};

impl VerificationAlgorithm<Bbs2023> for Bbs2023SignatureAlgorithm {
    fn verify(
        method: &Multikey,
        prepared_claims: HashData,
        proof: ProofRef<Bbs2023>,
    ) -> Result<ProofValidity, ProofValidationError> {
        match prepared_claims {
            HashData::Base(_) => Err(ProofValidationError::other(
                "selective disclosure base proof",
            )),
            HashData::Derived(t) => {
                // Verify Derived Proof algorithm.
                // See: <https://www.w3.org/TR/vc-di-bbs/#verify-derived-proof-bbs-2023>

                let DecodedMultikey::Bls12_381(public_key) = method.public_key.decode()? else {
                    return Err(ProofValidationError::InvalidKey);
                };

                let data =
                    create_verify_data3(&t.proof_hash, &t.canonical_id_map, &t.quads, proof)?;

                let mut bbs_header = [0; 64];
                bbs_header[..32].copy_from_slice(data.proof_hash);
                bbs_header[32..].copy_from_slice(&data.mandatory_hash);

                let disclosed_messages: Vec<_> = data
                    .non_mandatory
                    .into_iter()
                    .map(String::into_bytes)
                    .collect();

                match data.feature_option {
                    DerivedFeatureOption::Baseline => proof_verify(
                        public_key,
                        &data.base_signature,
                        &bbs_header,
                        data.presentation_header.as_deref(),
                        &disclosed_messages,
                        &data.selective_indexes,
                    ),
                    _ => Err(ProofValidationError::other("unimplemented feature option")),
                }
            }
        }
    }
}

struct VerifyData<'a> {
    base_signature: Vec<u8>,
    proof_hash: &'a [u8; 32],
    non_mandatory: Vec<String>,
    mandatory_hash: [u8; 32],
    selective_indexes: Vec<usize>,
    feature_option: DerivedFeatureOption,
    presentation_header: Option<Vec<u8>>,
}

/// See: <https://www.w3.org/TR/vc-di-bbs/#createverifydata>
fn create_verify_data3<'a>(
    proof_hash: &'a [u8; 32],
    canonical_id_map: &NormalizingSubstitution,
    quads: &[LexicalQuad],
    proof: ProofRef<Bbs2023>,
) -> Result<VerifyData<'a>, ProofValidationError> {
    let decoded_signature = proof.signature.decode_derived()?;

    let label_map_factory_function = create_label_map_function(&decoded_signature.label_map);

    let label_map = label_map_factory_function(canonical_id_map);
    let mut canonical_quads = relabel_quads(&label_map, quads).into_nquads_lines();
    canonical_quads.sort_unstable();
    canonical_quads.dedup();

    let mut mandatory = Vec::new();
    let mut non_mandatory = Vec::new();

    for (i, quad) in canonical_quads.into_iter().enumerate() {
        if decoded_signature
            .mandatory_indexes
            .binary_search(&i)
            .is_ok()
        {
            mandatory.push(quad)
        } else {
            non_mandatory.push(quad)
        }
    }

    let mandatory_hash: [u8; 32] = mandatory
        .iter()
        .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize()
        .into();

    Ok(VerifyData {
        base_signature: decoded_signature.bbs_proof,
        proof_hash,
        non_mandatory,
        mandatory_hash,
        selective_indexes: decoded_signature.selective_indexes,
        feature_option: decoded_signature.feature_option,
        presentation_header: decoded_signature.presentation_header,
    })
}

#[cfg(test)]
mod tests {
    use ssi_claims_core::VerificationParameters;
    use ssi_data_integrity_core::DataIntegrity;
    use ssi_verification_methods::Multikey;
    use static_iref::uri;
    use std::collections::HashMap;

    use crate::Bbs2023;

    use super::super::tests::*;

    #[async_std::test]
    async fn verify() {
        let document: DataIntegrity<JsonCredential, Bbs2023> =
            serde_json::from_str(include_str!("tests/signed-derived-document.jsonld")).unwrap();

        let verification_method = Multikey::from_public_key(
            VERIFICATION_METHOD_IRI.to_owned(),
            uri!("did:method:controller").to_owned(),
            &*PUBLIC_KEY,
        );

        let mut methods = HashMap::new();
        methods.insert(VERIFICATION_METHOD_IRI.to_owned(), verification_method);

        let params = VerificationParameters::from_resolver(methods);
        assert!(document.verify(params).await.unwrap().is_ok())
    }
}
