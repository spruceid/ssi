use ssi_data_integrity_core::{
    suite::standard::{HashingAlgorithm, HashingError, TransformationAlgorithm},
    ProofConfigurationRef, StandardCryptographicSuite,
};

pub struct Eip712Hashing;

impl<S> HashingAlgorithm<S> for Eip712Hashing
where
    S: StandardCryptographicSuite,
    S::Transformation: TransformationAlgorithm<S, Output = ssi_eip712::TypedData>,
{
    type Output = [u8; 66];

    fn hash(
        input: ssi_eip712::TypedData,
        _proof_configuration: ProofConfigurationRef<S>,
        _verification_method: &S::VerificationMethod,
    ) -> Result<Self::Output, HashingError> {
        input
            .encode()
            .map_err(|e| HashingError::InvalidMessage(e.to_string()))
    }
}
