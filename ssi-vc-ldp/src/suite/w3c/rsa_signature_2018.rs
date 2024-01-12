use ssi_crypto::MessageSigner;
use ssi_verification_methods::{
    covariance_rule, InvalidSignature, Referencable, RsaVerificationKey2018, SignatureError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, ProofConfigurationRef,
};

/// RSA Signature Suite 2018.
///
/// See: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaSignature2018;

impl RsaSignature2018 {
    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#RsaSignature2018");
}

impl_rdf_input_urdna2015!(RsaSignature2018);

impl CryptographicSuite for RsaSignature2018 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = RsaVerificationKey2018;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::RS256;

    type Options = ();

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
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm
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

impl From<Signature> for AnySignature {
    fn from(value: Signature) -> Self {
        AnySignature {
            signature_value: Some(value.signature_value),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base64-encoded signature value.
    pub signature_value: &'a str,
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.signature_value {
            Some(v) => Ok(Self { signature_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

/// Signature algorithm.
pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<RsaVerificationKey2018> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::RS256;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        _method: <RsaVerificationKey2018 as Referencable>::Reference<'_>,
        _bytes: &[u8],
        _signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        _signature: SignatureRef,
        _method: &RsaVerificationKey2018,
        _bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
