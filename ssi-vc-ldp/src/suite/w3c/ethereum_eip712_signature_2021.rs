//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use ssi_verification_methods::{
    signature, verification_method_union, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, JsonWebKey2020,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

/// Ethereum EIP-712 Signature 2021.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021;

impl_rdf_input_urdna2015!(EthereumEip712Signature2021);

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef
    where
        Signature = signature::Jws,
        ProofContext = ()
    {
        JsonWebKey2020,
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

#[async_trait::async_trait]
impl CryptographicSuite for EthereumEip712Signature2021 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<VerificationMethod>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#EthereumEip712Signature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }
}
