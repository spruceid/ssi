use crate::{
    key::{KeyConversionError, KeyMetadata},
    AlgorithmInstance, Error, KeyType, PublicKey, RejectedSignature, SecretKey,
    SignatureVerification, SigningKey, VerifyingKey,
};
pub use p256::ecdsa::{SigningKey as P256SecretKey, VerifyingKey as P256PublicKey};

use super::{EcdsaCurve, EcdsaPublicKey, EcdsaSecretKey};

impl PublicKey {
    /// Creates a new ECDSA P-256 public key.
    pub fn new_ecdsa_p256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::new_p256(x, y).map(Self::Ecdsa)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_ecdsa_p256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::from_p256_sec1_bytes(bytes).map(Self::Ecdsa)
    }
}

impl EcdsaPublicKey {
    /// Creates a new ECDSA P-256 public key.
    pub fn new_p256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);
        Self::from_p256_sec1_bytes(&bytes)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_p256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        P256PublicKey::from_sec1_bytes(bytes)
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for P256PublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Ecdsa(EcdsaCurve::P256)),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        match algorithm.into() {
            AlgorithmInstance::Es256 => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let verification = self.verify(signing_bytes, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            #[cfg(feature = "blake2")]
            AlgorithmInstance::EsBlake2b => {
                use digest::{consts::U32, Digest};
                use p256::ecdsa::signature::DigestVerifier;
                let sig = p256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let digest = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes);
                let verification = self.verify_digest(digest, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_ecdsa_p256() -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_p256())
    }

    pub fn generate_ecdsa_p256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_p256_from(rng))
    }

    pub fn new_ecdsa_p256(d: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaSecretKey::new_p256(d).map(Self::Ecdsa)
    }
}

impl EcdsaSecretKey {
    pub fn generate_p256() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p256_from(&mut rng)
    }

    pub fn generate_p256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P256(P256SecretKey::random(rng))
    }

    pub fn new_p256(d: &[u8]) -> Result<Self, KeyConversionError> {
        p256::SecretKey::from_bytes(d.into())
            .map(Into::into)
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for P256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use p256::ecdsa::{signature::Signer, Signature};
        match algorithm.into() {
            AlgorithmInstance::Es256 => {
                let signature: Signature = self.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().as_slice().into())
            }
            #[cfg(feature = "blake2")]
            AlgorithmInstance::EsBlake2b => {
                use digest::{consts::U32, Digest};
                use p256::ecdsa::signature::DigestSigner;
                let digest = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes);
                let signature: Signature = self.try_sign_digest(digest).unwrap();
                Ok(signature.to_bytes().as_slice().into())
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
        let secret_key = P256SecretKey::random(&mut OsRng);
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
    fn es256_roundtrip() {
        roundtrip(AlgorithmInstance::Es256);
    }

    #[cfg(feature = "blake2")]
    #[test]
    fn esblake2b_roundtrip() {
        roundtrip(AlgorithmInstance::EsBlake2b);
    }
}
