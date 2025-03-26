use crate::{
    hash,
    key::{KeyConversionError, KeyGenerationFailed, KeyMetadata},
    AlgorithmInstance, Error, PublicKey, RejectedSignature, SecretKey, SigningKey, VerifyingKey,
};
use rand::{CryptoRng, RngCore};
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
pub use rsa::{RsaPrivateKey as RsaSecretKey, RsaPublicKey};
use sha2::Sha256;

use super::{BitSize, KeyType};

impl PublicKey {
    /// Deserializes an ASN.1 DER-encoded `RsaPublicKey` (binary format).
    pub fn from_rsa_pkcs1_der(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        RsaPublicKey::from_pkcs1_der(bytes)
            .map(Self::Rsa)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SecretKey {
    pub fn generate_rsa_from(
        len: BitSize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, KeyGenerationFailed> {
        RsaSecretKey::new(rng, len.0)
            .map(Self::Rsa)
            .map_err(|_| KeyGenerationFailed::InvalidParameters)
    }
}

impl VerifyingKey for RsaPublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Rsa(BitSize(self.n().bits()))),
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
            AlgorithmInstance::Rs256 => {
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(self.clone());
                let signature = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                Ok(key
                    .verify(signing_bytes, &signature)
                    .map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::Ps256 => {
                let key = rsa::pss::VerifyingKey::<Sha256>::new(self.clone());
                let signature = rsa::pss::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                Ok(key
                    .verify(signing_bytes, &signature)
                    .map_err(|_| RejectedSignature::Mismatch))
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
    ) -> Result<Vec<u8>, Error> {
        match algorithm.into() {
            AlgorithmInstance::Rs256 => {
                let padding = rsa::Pkcs1v15Sign::new::<Sha256>();
                let digest_in = hash::sha256(signing_bytes);
                self.sign(padding, &digest_in).map_err(Error::internal)
            }
            AlgorithmInstance::Ps256 => {
                let mut rng = rand::rngs::OsRng {};
                let padding = rsa::Pss::new_with_salt::<Sha256>(32);
                let digest_in = hash::sha256(signing_bytes);
                self.sign_with_rng(&mut rng, padding, &digest_in)
                    .map_err(Error::internal)
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn roundtrip(algorithm: AlgorithmInstance) {
        let secret_key = RsaSecretKey::new(&mut OsRng, 1024).unwrap();
        let signature = secret_key
            .sign_bytes(algorithm.clone(), b"message")
            .unwrap();
        let public_key = secret_key.to_public_key();
        assert_eq!(
            public_key
                .verify_bytes(algorithm, b"message", &signature)
                .unwrap(),
            Ok(())
        )
    }

    #[test]
    fn rs256_roundtrip() {
        roundtrip(AlgorithmInstance::Rs256);
    }

    #[test]
    fn ps256_roundtrip() {
        roundtrip(AlgorithmInstance::Ps256);
    }
}
