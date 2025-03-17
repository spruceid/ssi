use ssi_claims_core::Parameters;
use ssi_crypto::{algorithm::DigestFunction, Error};

use crate::ProofRef;

pub async fn canonicalize_json_ld_claims_and_configuration<T, S>(
    claims: &T,
    configuration: ProofRef<'_, S>,
    params: &Parameters,
) -> Result<CanonicalClaimsAndConfiguration, Error> {
    todo!()
}

pub struct CanonicalClaimsAndConfiguration;

impl CanonicalClaimsAndConfiguration {
    pub fn hash(self, f: DigestFunction) -> Box<[u8]> {
        todo!()
    }
}
