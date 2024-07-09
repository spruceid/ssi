use k256::sha2::{Digest, Sha256};
use rdf_types::LexicalQuad;
use ssi_data_integrity_core::{
    suite::standard::{HashingAlgorithm, HashingError, TransformedData},
    ProofConfigurationRef,
};
use ssi_rdf::{urdna2015::NormalizingSubstitution, IntoNQuads};
use ssi_verification_methods::Multikey;

use crate::Bbs2023;

use super::{
    transformation::{TransformedBase, TransformedDerived},
    Transformed,
};

pub struct Bbs2023Hashing;

impl HashingAlgorithm<Bbs2023> for Bbs2023Hashing {
    type Output = HashData;

    fn hash(
        input: TransformedData<Bbs2023>,
        _proof_configuration: ProofConfigurationRef<Bbs2023>,
        _verification_method: &Multikey,
    ) -> Result<Self::Output, HashingError> {
        match input {
            Transformed::Base(t) => {
                // Base Proof Hashing algorithm.
                // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-hashing-bbs-2023>
                let proof_hash = t
                    .canonical_configuration
                    .iter()
                    .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize()
                    .into();

                let mandatory_hash = t
                    .mandatory
                    .iter()
                    .into_nquads_lines()
                    .into_iter()
                    .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize()
                    .into();

                Ok(HashData::Base(BaseHashData {
                    transformed_document: t,
                    proof_hash,
                    mandatory_hash,
                }))
            }
            Transformed::Derived(t) => Ok(HashData::Derived(create_verify_data2(t))),
        }
    }
}

// See: https://www.w3.org/TR/vc-di-bbs/#createverifydata
fn create_verify_data2(t: TransformedDerived) -> DerivedHashData {
    let proof_hash = t
        .canonical_configuration
        .iter()
        .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize()
        .into();

    DerivedHashData {
        canonical_configuration: t.canonical_configuration,
        quads: t.quads,
        canonical_id_map: t.canonical_id_map,
        proof_hash,
    }
}

#[derive(Debug, Clone)]
pub enum HashData {
    Base(BaseHashData),
    Derived(DerivedHashData),
}

#[derive(Debug, Clone)]
pub struct BaseHashData {
    pub transformed_document: TransformedBase,
    pub proof_hash: [u8; 32],
    pub mandatory_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct DerivedHashData {
    pub canonical_configuration: Vec<String>,
    pub quads: Vec<LexicalQuad>,
    pub canonical_id_map: NormalizingSubstitution,
    pub proof_hash: [u8; 32],
}
