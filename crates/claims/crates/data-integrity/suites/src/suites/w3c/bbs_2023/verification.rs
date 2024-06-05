use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_data_integrity_core::{suite::standard::VerificationAlgorithm, ProofRef};
use ssi_verification_methods::Multikey;

use crate::Bbs2023;

use super::{Bbs2023SignatureAlgorithm, HashData};

impl VerificationAlgorithm<Bbs2023> for Bbs2023SignatureAlgorithm {
    fn verify(
        method: &Multikey,
        prepared_claims: HashData,
        proof: ProofRef<Bbs2023>,
    ) -> Result<ProofValidity, ProofValidationError> {
        match prepared_claims {
            HashData::Base(_) => {
                todo!()
            }
            HashData::Derived(t) => {
                // Verify Derived Proof algorithm.
                // See: <https://www.w3.org/TR/vc-di-bbs/#verify-derived-proof-bbs-2023>
                // let proof_hash, mandatory_hash = createVerifyData, step 2, 5, 6, 7, 8, 9
                // let bbs_header = proof_hash + mandatory_hash
                // let disclosed_messages = ...
                todo!()
            }
        }
    }
}
