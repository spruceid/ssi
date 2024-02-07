use super::{Options, OptionsRef};
use iref::Iri;
use ssi_crypto::MessageSigner;
use ssi_verification_methods::{
    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, SignatureError, VerificationError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef},
    CryptographicSuite, ProofConfigurationRef,
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    pub const NAME: &'static str = "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021";

    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021");
}

impl_rdf_input_urdna2015!(Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

impl CryptographicSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdBlake2b;

    type Options = Options;

    fn name(&self) -> &str {
        Self::NAME
    }

    fn iri(&self) -> &iref::Iri {
        Self::IRI
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

impl
    ssi_verification_methods::SignatureAlgorithm<
        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    > for SignatureAlgorithm
{
    type Options = Options;

    type Signature = JwsSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdBlake2b;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 as ssi_core::Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(
            bytes,
            signer,
            options.public_key_jwk.key_id.clone(),
            ssi_jwk::algorithm::EdBlake2b,
        )
        .await
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: JwsSignatureRef,
        method: &Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        if method.matches_public_key(options.public_key_jwk)? {
            let (header, _, signature) = signature
                .jws
                .decode()
                .map_err(|_| VerificationError::InvalidSignature)?;
            let signing_bytes = header.encode_signing_bytes(bytes);
            Ok(ssi_jws::verify_bytes(
                header.algorithm,
                &signing_bytes,
                options.public_key_jwk,
                &signature,
            )
            .is_ok())
        } else {
            Ok(false)
        }
    }
}
