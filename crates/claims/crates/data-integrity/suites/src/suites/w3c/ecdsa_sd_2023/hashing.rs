use ssi_data_integrity_core::{suite::standard, ProofConfigurationRef};
use ssi_di_sd_primitives::{ShaAny, ShaAnyBytes};
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::Multikey;

use crate::EcdsaSd2023;

use super::{Transformed, TransformedBase};

pub struct HashingAlgorithm;

pub enum HashData {
    Base(BaseHashData),
    Derived,
}

#[derive(Debug, Clone)]
pub struct BaseHashData {
    pub transformed_document: TransformedBase,
    pub proof_hash: ShaAnyBytes,
    pub mandatory_hash: ShaAnyBytes,
}

impl standard::HashingAlgorithm<EcdsaSd2023> for HashingAlgorithm {
    type Output = HashData;

    fn hash(
        input: Transformed,
        proof_configuration: ProofConfigurationRef<'_, EcdsaSd2023>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, standard::HashingError> {
        match input {
            Transformed::Base(t) => {
                let sha = t.hmac_key.algorithm();

                let proof_hash = sha.hash_all(&t.canonical_configuration);
                let mandatory_hash = sha.hash_all(t.mandatory.iter().into_nquads_lines());

                Ok(HashData::Base(BaseHashData {
                    transformed_document: t,
                    proof_hash,
                    mandatory_hash,
                }))
            }
            Transformed::Derived => {
                todo!()
            }
        }
    }
}
