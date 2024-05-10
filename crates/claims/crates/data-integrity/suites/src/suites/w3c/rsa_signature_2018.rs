use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_core::{covariance_rule, Referencable};
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{MessageSigner, RsaVerificationKey2018};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, suites::sha256_hash};

/// RSA Signature Suite 2018.
///
/// See: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaSignature2018;

impl RsaSignature2018 {
    pub const NAME: &'static str = "RsaSignature2018";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#RsaSignature2018");
}

impl_rdf_input_urdna2015!(RsaSignature2018);

impl CryptographicSuite for RsaSignature2018 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = RsaVerificationKey2018;

    type Signature = Signature;

    type SignatureProtocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::RS256;

    type Options = ();

    fn name(&self) -> &str {
        Self::NAME
    }

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    async fn sign_hash(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        _method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        let signature = signer.sign(ssi_jwk::algorithm::RS256, (), bytes).await?;

        Ok(Signature {
            signature_value: base64::encode(signature),
        })
    }

    fn verify_hash(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as Referencable>::Reference<'_>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature = base64::decode(signature.signature_value)
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        method.verify_bytes(bytes, &signature).map(Into::into)
    }
}

/// Signature type.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Base64-encoded signature value.
    pub signature_value: String,
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            signature_value: &self.signature_value,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base64-encoded signature value.
    pub signature_value: &'a str,
}
