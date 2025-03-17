//! `ecdsa-rdfc-2019` cryptosuite implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019>
use multibase::Base;
use ssi_crypto::{
    algorithm::DigestFunction, key::KeyMetadata, AlgorithmInstance, Error, KeyType,
    SignatureVerification, Signer,
};
use ssi_data_integrity_core::{CryptographicSuiteFor, Proof, ProofRef, StaticCryptographicSuite};
use ssi_jwk::VerifyingKey;

use ssi_data_integrity_core::primitives::{
    multibase::{multibase_signing, multibase_verification},
    rdf::canonicalize_json_ld_claims_and_configuration,
};

/// The `ecdsa-rdfc-2019` cryptosuite.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaRdfc2019;

impl StaticCryptographicSuite for EcdsaRdfc2019 {
    const CRYPTO_SUITE: &str = "ecdsa-rdfc-2019";
}

impl<T> CryptographicSuiteFor<T> for EcdsaRdfc2019 {
    type PreparedClaims = (Box<[u8]>, AlgorithmInstance);

    async fn prepare(
        claims: &T,
        configuration: ProofRef<'_, Self>,
        key_metadata: KeyMetadata,
        params: &ssi_claims_core::Parameters,
    ) -> Result<Self::PreparedClaims, Error> {
        let (digest, algorithm) = match key_metadata.r#type {
            Some(KeyType::P256) => (DigestFunction::Sha256, AlgorithmInstance::ES256),
            Some(KeyType::P384) => (DigestFunction::Sha384, AlgorithmInstance::PS384),
            _ => return Err(Error::KeyUnsupported),
        };

        let hash = canonicalize_json_ld_claims_and_configuration(claims, configuration, params)
            .await?
            .hash(digest);

        Ok((hash, algorithm))
    }

    async fn generate_proof(
        signer: impl Signer,
        (claims, algorithm): Self::PreparedClaims,
        configuration: Proof<Self>,
        _params: &ssi_claims_core::Parameters,
    ) -> Result<Proof<Self>, Error> {
        multibase_signing(
            signer,
            claims,
            configuration,
            Some(algorithm),
            Base::Base58Btc,
        )
        .await
    }

    async fn verify_proof(
        verifier: impl VerifyingKey,
        (claims, algorithm): Self::PreparedClaims,
        proof: ProofRef<'_, Self>,
        _params: &ssi_claims_core::Parameters,
    ) -> Result<SignatureVerification, Error> {
        multibase_verification(verifier, claims, proof, Some(algorithm)).await
    }
}
