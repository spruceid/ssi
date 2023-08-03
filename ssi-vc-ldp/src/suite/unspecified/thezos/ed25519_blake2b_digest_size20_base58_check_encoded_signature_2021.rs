use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use ssi_verification_methods::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    CryptographicSuite, ProofConfiguration
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl_rdf_input_urdna2015!(Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

impl CryptographicSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct Signature {
    /// JSON Web Signature.
    jws: CompactJWSString,

    /// Signing key.
    public_key_jwk: Box<JWK>
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021> for SignatureAlgorithm {
    type Signature = Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
            &self,
            method: &Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
            bytes: &[u8],
            signer: &S
        ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(&self,
        signature: &Self::Signature,
        method: &Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
        bytes: &[u8]
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}