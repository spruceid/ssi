use ssi_verification_methods::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl_rdf_input_urdna2015!(Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

#[async_trait::async_trait]
impl CryptographicSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<
        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    >;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }
}
