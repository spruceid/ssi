use std::future;

use ssi_crypto::MessageSigner;
use ssi_jwk::Algorithm;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_verification_methods::{EcdsaSecp256k1RecoveryMethod2020, Referencable, SignatureError};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef, SignIntoDetachedJws},
    CryptographicSuite, ProofConfiguration, ProofConfigurationRef,
};

/// `EcdsaSecp256k1RecoverySignature2020`.
///
/// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
pub struct EcdsaSecp256k1RecoverySignature2020;

impl_rdf_input_urdna2015!(EcdsaSecp256k1RecoverySignature2020);

impl CryptographicSuite for EcdsaSecp256k1RecoverySignature2020 {
    type Transformed = String;

    type Hashed = [u8; 64];

    type VerificationMethod = EcdsaSecp256k1RecoveryMethod2020;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#EcdsaSecp256k1RecoverySignature2020")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<EcdsaSecp256k1RecoveryMethod2020>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = JwsSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> = SignIntoDetachedJws<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        _options: (),
        method: &EcdsaSecp256k1RecoveryMethod2020,
        bytes: &[u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        let header = ssi_jws::Header::new_unencoded(
            Algorithm::ES256KR,
            Some(method.id.as_str().to_owned())
        );

        SignIntoDetachedJws::new(header, bytes.to_vec(), signer)
    }

    fn verify(
        &self,
        options: (),
        signature: JwsSignatureRef,
        method: &EcdsaSecp256k1RecoveryMethod2020,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
