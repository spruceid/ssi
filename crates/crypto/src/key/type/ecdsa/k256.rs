use crate::{
    key::{KeyConversionError, KeyMetadata},
    AlgorithmInstance, Error, KeyType, PublicKey, RecoveryKey, RejectedSignature, SecretKey,
    SignatureVerification, SigningKey, VerifyingKey,
};
pub use k256::ecdsa::{SigningKey as K256SecretKey, VerifyingKey as K256PublicKey};
use sha2::Digest;

use super::{EcdsaCurve, EcdsaPublicKey, EcdsaSecretKey};

impl PublicKey {
    /// Creates a new ECDSA K-256 public key.
    pub fn new_ecdsa_k256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::new_k256(x, y).map(Self::Ecdsa)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_ecdsa_k256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::from_k256_sec1_bytes(bytes).map(Self::Ecdsa)
    }
}

impl EcdsaPublicKey {
    /// Creates a new ECDSA K-256 public key.
    pub fn new_k256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);
        Self::from_k256_sec1_bytes(&bytes)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_k256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        K256PublicKey::from_sec1_bytes(bytes)
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for K256PublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Ecdsa(EcdsaCurve::K256)),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        use k256::ecdsa::signature::{DigestVerifier, Verifier};
        match algorithm.into() {
            AlgorithmInstance::Es256K => {
                let sig = k256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let verification = self.verify(signing_bytes, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::Es256Kr => {
                let recovered_key =
                    Self::recover(AlgorithmInstance::Es256Kr, signing_bytes, signature)?;
                if recovered_key == *self {
                    Ok(Ok(()))
                } else {
                    Ok(Err(RejectedSignature::Mismatch))
                }
            }
            #[cfg(feature = "blake2")]
            AlgorithmInstance::EsBlake2bK => {
                use digest::consts::U32;
                let sig = k256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let digest = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes);
                let verification = self.verify_digest(digest, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            #[cfg(feature = "keccak")]
            AlgorithmInstance::EsKeccakK => {
                let sig = k256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let digest = sha3::Keccak256::new_with_prefix(signing_bytes);
                let verification = self.verify_digest(digest, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            #[cfg(feature = "keccak")]
            AlgorithmInstance::EsKeccakKr => {
                let recovered_key =
                    Self::recover(AlgorithmInstance::EsKeccakKr, signing_bytes, signature)?;
                if recovered_key == *self {
                    Ok(Ok(()))
                } else {
                    Ok(Err(RejectedSignature::Mismatch))
                }
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl RecoveryKey for K256PublicKey {
    fn recover(
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        match algorithm.into() {
            AlgorithmInstance::Es256Kr => {
                if signature.len() != 65 {
                    return Err(Error::SignatureMalformed);
                }

                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(|_| Error::SignatureMalformed)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(|_| Error::SignatureMalformed)?;

                k256::ecdsa::VerifyingKey::recover_from_digest(
                    sha2::Sha256::new_with_prefix(signing_bytes),
                    &sig,
                    rec_id,
                )
                .map_err(|_| Error::SignatureMalformed)
            }
            AlgorithmInstance::EsKeccakKr => {
                if signature.len() != 65 {
                    return Err(Error::SignatureMalformed);
                }

                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(|_| Error::SignatureMalformed)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(|_| Error::SignatureMalformed)?;

                k256::ecdsa::VerifyingKey::recover_from_digest(
                    sha3::Keccak256::new_with_prefix(signing_bytes),
                    &sig,
                    rec_id,
                )
                .map_err(|_| Error::SignatureMalformed)
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_ecdsa_k256() -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_k256())
    }

    pub fn generate_ecdsa_k256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_k256_from(rng))
    }

    pub fn new_ecdsa_k256(d: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaSecretKey::new_k256(d).map(Self::Ecdsa)
    }
}

impl EcdsaSecretKey {
    pub fn generate_k256() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_k256_from(&mut rng)
    }

    pub fn generate_k256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::K256(k256::SecretKey::random(rng).into())
    }

    pub fn new_k256(d: &[u8]) -> Result<Self, KeyConversionError> {
        k256::SecretKey::from_bytes(d.into())
            .map(Into::into)
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for K256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use k256::ecdsa::{
            signature::{DigestSigner, Signer},
            Signature,
        };

        match algorithm.into() {
            AlgorithmInstance::Es256K => {
                let signature: Signature = self.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().to_vec())
            }
            AlgorithmInstance::Es256Kr => {
                // NOTE: explicitly using SHA256 here because the default hash
                //       function provided by the `k256` crate for recovery has
                //       varied over time across different versions.
                let digest = sha2::Sha256::new_with_prefix(signing_bytes);
                let (sig, rec_id) = self
                    .sign_digest_recoverable(digest)
                    .map_err(Error::internal)?;

                let mut result = sig.to_vec();
                result.push(rec_id.to_byte());
                Ok(result)
            }
            #[cfg(feature = "blake2")]
            AlgorithmInstance::EsBlake2bK => {
                use digest::consts::U32;
                let digest = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes);
                let signature: Signature = self.try_sign_digest(digest).unwrap();
                Ok(signature.to_bytes().to_vec())
            }
            #[cfg(feature = "keccak")]
            AlgorithmInstance::EsKeccakK => {
                let digest = sha3::Keccak256::new_with_prefix(signing_bytes);
                let signature: Signature = self.try_sign_digest(digest).unwrap();
                Ok(signature.to_bytes().to_vec())
            }
            #[cfg(feature = "keccak")]
            AlgorithmInstance::EsKeccakKr => {
                let digest = sha3::Keccak256::new_with_prefix(signing_bytes);
                let (sig, rec_id) = self
                    .sign_digest_recoverable(digest)
                    .map_err(Error::internal)?;
                let mut result = sig.to_vec();
                result.push(rec_id.to_byte());
                Ok(result)
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
        let secret_key = K256SecretKey::random(&mut OsRng);
        let signature = secret_key
            .sign_bytes(algorithm.clone(), b"message")
            .unwrap();
        let public_key = *secret_key.verifying_key();
        assert_eq!(
            public_key
                .verify_bytes(algorithm, b"message", &signature)
                .unwrap(),
            Ok(())
        )
    }

    #[test]
    fn es256k_roundtrip() {
        roundtrip(AlgorithmInstance::Es256K);
    }

    #[test]
    fn es256kr_roundtrip() {
        roundtrip(AlgorithmInstance::Es256Kr);
    }

    #[cfg(feature = "blake2")]
    #[test]
    fn esblake2bk_roundtrip() {
        roundtrip(AlgorithmInstance::EsBlake2bK);
    }

    #[cfg(feature = "keccak")]
    #[test]
    fn eskeccakk_roundtrip() {
        roundtrip(AlgorithmInstance::EsKeccakK);
    }

    #[cfg(feature = "keccak")]
    #[test]
    fn eskeccakkr_roundtrip() {
        roundtrip(AlgorithmInstance::EsKeccakKr);
    }
}
