use base64::Engine;
use k256::sha2::Sha256;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    suite::{
        standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm},
        NoConfiguration,
    },
    ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::{MessageSigner, RsaVerificationKey2018};
use static_iref::iri;

use crate::try_from_type;

/// RSA Signature Suite 2018.
///
/// See: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaSignature2018;

impl RsaSignature2018 {
    pub const NAME: &'static str = "RsaSignature2018";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#RsaSignature2018");
}

impl StandardCryptographicSuite for RsaSignature2018 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = RsaVerificationKey2018;

    type SignatureAlgorithm = RsaSignatureAlgorithm;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(RsaSignature2018);

/// Signature type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    /// Base64-encoded signature value.
    pub signature_value: String,
}

impl AsRef<str> for Signature {
    fn as_ref(&self) -> &str {
        &self.signature_value
    }
}

impl ssi_data_integrity_core::signing::AlterSignature for Signature {
    fn alter(&mut self) {
        self.signature_value.push_str("ff")
    }
}

pub struct RsaSignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for RsaSignatureAlgorithm {
    type Signature = Signature;
}

impl<T> SignatureAlgorithm<RsaSignature2018, T> for RsaSignatureAlgorithm
where
    T: MessageSigner<ssi_crypto::algorithm::RS256>,
{
    async fn sign(
        _verification_method: &RsaVerificationKey2018,
        signer: T,
        prepared_claims: [u8; 64],
        _proof_configuration: ProofConfigurationRef<'_, RsaSignature2018>,
    ) -> Result<Signature, SignatureError> {
        let signature = signer
            .sign(ssi_crypto::algorithm::RS256, &prepared_claims)
            .await?;

        Ok(Signature {
            signature_value: base64::prelude::BASE64_STANDARD.encode(signature),
        })
    }
}

impl VerificationAlgorithm<RsaSignature2018> for RsaSignatureAlgorithm {
    fn verify(
        method: &RsaVerificationKey2018,
        prepared_claims: [u8; 64],
        proof: ProofRef<RsaSignature2018>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature = base64::prelude::BASE64_STANDARD
            .decode(&proof.signature.signature_value)
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        method
            .verify_bytes(&prepared_claims, &signature)
            .map(Into::into)
    }
}
