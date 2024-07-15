use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_data_integrity_core::{suite::standard::VerificationAlgorithm, ProofRef};
use ssi_verification_methods::Multikey;

use crate::EcdsaSd2023;

use super::{HashData, SignatureAlgorithm};

impl VerificationAlgorithm<EcdsaSd2023> for SignatureAlgorithm {
    fn verify(
        method: &Multikey,
        prepared_claims: HashData,
        proof: ProofRef<'_, EcdsaSd2023>,
    ) -> Result<ProofValidity, ProofValidationError> {
        todo!()
    }
}
