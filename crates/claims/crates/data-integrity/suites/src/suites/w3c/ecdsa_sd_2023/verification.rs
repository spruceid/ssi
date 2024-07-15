use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_data_integrity_core::{suite::standard::VerificationAlgorithm, ProofRef};
use ssi_di_sd_primitives::{canonicalize::{create_label_map_function, relabel_quads}, ShaAny, ShaAnyBytes};
use ssi_multicodec::MultiEncodedBuf;
use ssi_rdf::{urdna2015::NormalizingSubstitution, IntoNQuads, LexicalQuad};
use ssi_verification_methods::Multikey;

use crate::{ecdsa_sd_2023::serialize_sign_data, EcdsaSd2023};

use super::{HashData, SignatureAlgorithm};

impl VerificationAlgorithm<EcdsaSd2023> for SignatureAlgorithm {
    fn verify(
        method: &Multikey,
        prepared_claims: HashData,
        proof: ProofRef<'_, EcdsaSd2023>,
    ) -> Result<ProofValidity, ProofValidationError> {
        match prepared_claims {
            HashData::Base(_) => Err(ProofValidationError::other(
                "selective disclosure base proof",
            )),
            HashData::Derived(t) => {
                let data =
                    create_verify_data3(&t.proof_hash, &t.canonical_id_map, &t.quads, proof)?;

                if data.signatures.len() != data.non_mandatory.len() {
                    return Err(ProofValidationError::InvalidSignature)
                }

                let to_verify = serialize_sign_data(
                    t.proof_hash,
                    data.mandatory_hash,
                    &data.public_key
                );

                // let public_key: p256::PublicKey = data
                //     .public_key
                //     .decode()
                //     .map_err(|_| ProofValidationError::InvalidSignature)?;

                todo!()
            }
        }
    }
}

struct VerifyData<'a> {
    base_signature: Vec<u8>,
    proof_hash: &'a ShaAnyBytes,
    public_key: MultiEncodedBuf,
    signatures: Vec<Vec<u8>>,
    non_mandatory: Vec<LexicalQuad>,
    mandatory_hash: ShaAnyBytes
}

/// See: <https://www.w3.org/TR/vc-di-bbs/#createverifydata>
fn create_verify_data3<'a>(
    proof_hash: &'a ShaAnyBytes,
    canonical_id_map: &NormalizingSubstitution,
    quads: &[LexicalQuad],
    proof: ProofRef<EcdsaSd2023>,
) -> Result<VerifyData<'a>, ProofValidationError> {
    let decoded_signature = proof
        .signature
        .decode_derived()?;

    let label_map_factory_function = create_label_map_function(&decoded_signature.label_map);

    let label_map = label_map_factory_function(canonical_id_map);
    let mut canonical_quads = relabel_quads(&label_map, quads);
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

    let mandatory_hash: ShaAnyBytes = 
        ShaAny::Sha256.hash_all(
            mandatory
                .iter()
                .into_nquads_lines()
        );

    Ok(VerifyData {
        base_signature: decoded_signature.base_signature,
        proof_hash,
        public_key: decoded_signature.public_key,
        signatures: decoded_signature.signatures,
        non_mandatory,
        mandatory_hash
    })
}
