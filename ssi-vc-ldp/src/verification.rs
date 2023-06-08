use ssi_crypto::VerifierProvider;
use ssi_vc::ProofValidity;

use crate::{suite::VerificationParameters, DataIntegrity, Proof, VerifiableCryptographicSuite};

impl<T, S, M> ssi_vc::VerifiableWith<Proof<S, M>> for DataIntegrity<T>
where
    S: VerifiableCryptographicSuite<M>,
{
    type Method = M;

    type Transformed = S::Transformed;
    type Parameters = S::VerificationParameters;

    type Error = S::Error;

    fn verify_with(
        &self,
        context: &mut impl ssi_vc::Context<Self, Proof<S, M>>,
        verifiers: &impl VerifierProvider<Self::Method>,
        proof: &Proof<S, M>,
        parameters: Self::Parameters,
    ) -> Result<ProofValidity, S::Error> {
        let transformed = context.transform(self, &proof, &parameters)?;
        let suite = &proof.type_;
        let hash = suite.hash(transformed, parameters.into_hash_parameters())?;
        suite.verify_proof(hash, verifiers, &proof)
    }
}
