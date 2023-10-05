use std::future;

use ssi_crypto::MessageSigner;
use ssi_verification_methods::{EcdsaSecp256r1VerificationKey2019, SignatureError};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, MultibaseSignature, MultibaseSignatureRef},
    CryptographicSuite, ProofConfigurationRef,
};

/// ECDSA Cryptosuite v2019 `EcdsaSecp256r1Signature2019`.
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
pub struct EcdsaSecp256r1Signature2019;

impl_rdf_input_urdna2015!(EcdsaSecp256r1Signature2019);

impl CryptographicSuite for EcdsaSecp256r1Signature2019 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = EcdsaSecp256r1VerificationKey2019;

    type Signature = MultibaseSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#EcdsaSecp256r1Signature2019")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<EcdsaSecp256r1VerificationKey2019>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = MultibaseSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        _options: (),
        method: &EcdsaSecp256r1VerificationKey2019,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        signature: MultibaseSignatureRef,
        method: &EcdsaSecp256r1VerificationKey2019,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
