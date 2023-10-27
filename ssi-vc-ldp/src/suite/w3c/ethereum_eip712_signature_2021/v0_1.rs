use ssi_verification_methods::Referencable;
use static_iref::iri;

use crate::{CryptographicSuite, eip712::{Eip712Signature, TypesProvider}, ProofConfigurationRef, suite::HashError, CryptographicSuiteInput};

use super::{VerificationMethod, SignatureAlgorithm, Options, Transform};

#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021v0_1;

impl EthereumEip712Signature2021v0_1 {
    pub const IRI: &iref::Iri = iri!("https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021");
}

impl CryptographicSuite for EthereumEip712Signature2021v0_1 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 32];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyES256K;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: ssi_eip712::TypedData,
        _proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        data.hash()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl<T: serde::Serialize, C: TypesProvider> CryptographicSuiteInput<T, C> for EthereumEip712Signature2021v0_1
where
    for<'a> <Self::VerificationMethod as Referencable>::Reference<'a>: serde::Serialize,
    for<'a> <Self::Options as Referencable>::Reference<'a>: serde::Serialize
{
    type Transform<'a> = Transform<'a, C> where Self: 'a, T: 'a, C: 'a;
        
    fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: C,
        params: ProofConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Self::Transform<'a> where C: 'a {
        super::EthereumEip712Signature2021::transform(
			&super::EthereumEip712Signature2021,
			data,
			context,
			params
		)
    }
}