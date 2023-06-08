use ssi_crypto::Signer;
use ssi_vc::Verifiable;

use crate::{
    CryptographicSuite, CryptographicSuiteInput, DataIntegrity, LinkedDataCredential, Proof,
};

pub trait SignerProvider<M> {
    type Signer<'a>: Signer
    where
        Self: 'a;

    fn get_signer(&self, method: &M) -> Self::Signer<'_>;
}

pub trait SignParams<M, S: CryptographicSuite<M>> {
    fn transform_params(&self) -> S::TransformationParameters;

    fn hash_params(&self) -> S::HashParameters;

    fn into_proof_params(self) -> S::ProofParameters;
}

/// Credential signing.
pub trait Sign<C>: Sized {
    fn sign<M, S: CryptographicSuite<M> + CryptographicSuiteInput<Self, M, C>>(
        self,
        suite: S,
        context: &mut C,
        signer_provider: &impl SignerProvider<M>,
        params: impl SignParams<M, S>,
    ) -> Result<Verifiable<DataIntegrity<Self>, Proof<S, M>>, (Self, S::Error)> {
        match suite.transform(context, &self, params.transform_params()) {
            Ok(transformed) => match suite.hash(transformed, params.hash_params()) {
                Ok(hash) => {
                    match suite.generate_proof(hash, signer_provider, params.into_proof_params()) {
                        Ok(proof) => Ok(Verifiable::new(DataIntegrity(self), proof)),
                        Err(e) => Err((self, e)),
                    }
                }
                Err(e) => Err((self, e)),
            },
            Err(e) => Err((self, e)),
        }
    }
}

impl<T: LinkedDataCredential<C>, C> Sign<C> for T {}
