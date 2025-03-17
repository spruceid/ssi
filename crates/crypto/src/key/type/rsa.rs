use crate::{
    hashes, key::{KeyConversionError, KeyMetadata}, AlgorithmInstance, Error, PublicKey, RejectedSignature, SigningKey, VerifyingKey
};
use rsa::pkcs1::DecodeRsaPublicKey;
pub use rsa::{RsaPrivateKey as RsaSecretKey, RsaPublicKey};
use sha2::Sha256;

use super::KeyType;

impl PublicKey {
    /// Deserializes an ASN.1 DER-encoded `RsaPublicKey` (binary format).
    pub fn from_rsa_pkcs1_der(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        RsaPublicKey::from_pkcs1_der(bytes)
            .map(Self::Rsa)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for RsaPublicKey {
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Rsa),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::SignatureVerification, crate::Error> {
        use rsa::signature::Verifier;
        match algorithm.into() {
            AlgorithmInstance::RS256 => {
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(self.clone());
                let signature = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                Ok(key.verify(signing_bytes, &signature).map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::PS256 => {
                let key = rsa::pss::VerifyingKey::<Sha256>::new(self.clone());
                let signature = rsa::pss::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                Ok(key.verify(signing_bytes, &signature).map_err(|_| RejectedSignature::Mismatch))
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SigningKey for RsaSecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match algorithm.into() {
            AlgorithmInstance::RS256 => {
                let padding = rsa::Pkcs1v15Sign::new::<Sha256>();
                let digest_in = hashes::sha256::sha256(signing_bytes);
                self.sign(padding, &digest_in)
                    .map(Vec::into_boxed_slice)
                    .map_err(Error::internal)
            }
            AlgorithmInstance::PS256 => {
                let mut rng = rand::rngs::OsRng {};
                let padding = rsa::Pss::new_with_salt::<Sha256>(32);
                let digest_in = hashes::sha256::sha256(signing_bytes);
                self.sign_with_rng(&mut rng, padding, &digest_in)
                    .map(Vec::into_boxed_slice)
                    .map_err(Error::internal)
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
