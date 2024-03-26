use crate::{impl_rdf_input_urdna2015, suites::sha256_hash, JwsSignature};

use super::{Options, TZ_CONTEXT};
use iref::Iri;
use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{
    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, SignatureError, VerificationError,
};
use static_iref::iri;

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
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(json_ld::syntax::Context::One(TZ_CONTEXT.clone()))
    }

    async fn sign_hash(
        &self,
        options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(
            bytes,
            signer,
            options.public_key_jwk.key_id.clone(),
            ssi_jwk::algorithm::EdBlake2b,
        )
        .await
    }

    fn verify_hash(
        &self,
        options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as ssi_core::Referencable>::Reference<'_>,
    ) -> Result<ssi_claims_core::ProofValidity, VerificationError> {
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
            .is_ok()
            .into())
        } else {
            Ok(ssi_claims_core::ProofValidity::Invalid)
        }
    }
}
