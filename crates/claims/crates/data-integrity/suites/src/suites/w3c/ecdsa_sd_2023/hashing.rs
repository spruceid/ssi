use ssi_data_integrity_core::{
    suite::standard::{self, HashingError},
    ProofConfigurationRef,
};
use ssi_di_sd_primitives::{ShaAny, ShaAnyBytes};
use ssi_rdf::{urdna2015::NormalizingSubstitution, IntoNQuads, LexicalQuad};
use ssi_verification_methods::{multikey::DecodedMultikey, Multikey};

use crate::EcdsaSd2023;

use super::{Transformed, TransformedBase, TransformedDerived};

pub struct HashingAlgorithm;

#[derive(Debug, Clone)]
pub enum HashData {
    Base(Box<BaseHashData>),
    Derived(Box<DerivedHashData>),
}

#[derive(Debug, Clone)]
pub struct BaseHashData {
    pub transformed_document: TransformedBase,
    pub proof_hash: ShaAnyBytes,
    pub mandatory_hash: ShaAnyBytes,
}

#[derive(Debug, Clone)]
pub struct DerivedHashData {
    pub canonical_configuration: Vec<String>,
    pub quads: Vec<LexicalQuad>,
    pub canonical_id_map: NormalizingSubstitution,
    pub proof_hash: ShaAnyBytes,
}

impl standard::HashingAlgorithm<EcdsaSd2023> for HashingAlgorithm {
    type Output = HashData;

    fn hash(
        input: Transformed,
        _proof_configuration: ProofConfigurationRef<'_, EcdsaSd2023>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, standard::HashingError> {
        match input {
            Transformed::Base(t) => {
                let sha = t.hmac_key.algorithm();

                let proof_hash = sha.hash_all(&t.canonical_configuration);
                let mandatory_hash = sha.hash_all(t.mandatory.iter().into_nquads_lines());

                Ok(HashData::Base(Box::new(BaseHashData {
                    transformed_document: t,
                    proof_hash,
                    mandatory_hash,
                })))
            }
            Transformed::Derived(t) => {
                let decoded_key = verification_method
                    .public_key
                    .decode()
                    .map_err(|_| HashingError::InvalidKey)?;

                let sha = match decoded_key {
                    #[cfg(feature = "secp256r1")]
                    DecodedMultikey::P256(_) => ShaAny::Sha256,
                    #[cfg(feature = "secp384r1")]
                    DecodedMultikey::P384(_) => ShaAny::Sha384,
                    _ => return Err(HashingError::InvalidKey),
                };

                Ok(HashData::Derived(Box::new(create_verify_data2(t, sha))))
            }
        }
    }
}

fn create_verify_data2(t: TransformedDerived, sha: ShaAny) -> DerivedHashData {
    let proof_hash = sha.hash_all(&t.canonical_configuration);

    DerivedHashData {
        canonical_configuration: t.canonical_configuration,
        quads: t.quads,
        canonical_id_map: t.canonical_id_map,
        proof_hash,
    }
}
