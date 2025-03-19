use crate::{
    key::{KeyConversionError, KeyMetadata},
    AlgorithmInstance, Error, KeyType, PublicKey, RejectedSignature, SecretKey,
    SignatureVerification, SigningKey, VerifyingKey,
};
pub use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};

use super::{EdDsaKeyType, EdDsaPublicKey, EdDsaSecretKey};

impl PublicKey {
    /// Decodes an EdDSA Ed25519 public key encoded as specified in
    /// [RFC8032 Section 3.1][1]
    ///
    /// [1]: <https://www.rfc-editor.org/rfc/rfc8032#section-3.1>
    pub fn from_ed25519_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        EdDsaPublicKey::from_curve25519_bytes(bytes).map(Self::EdDsa)
    }
}

impl EdDsaPublicKey {
    /// Decodes an EdDSA Ed25519 public key encoded as specified in
    /// [RFC8032 Section 3.1][1]
    ///
    /// [1]: <https://www.rfc-editor.org/rfc/rfc8032#section-3.1>
    pub fn from_curve25519_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let bytes = bytes.try_into().map_err(|_| KeyConversionError::Invalid)?;
        Ed25519PublicKey::from_bytes(bytes)
            .map(Self::Curve25519)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for Ed25519PublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::EdDsa(EdDsaKeyType::Curve25519)),
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
            AlgorithmInstance::EdDsa => {
                use ed25519_dalek::Verifier;
                let signature: ed25519_dalek::Signature = signature
                    .try_into()
                    .map_err(|_| Error::SignatureMalformed)?;
                Ok(self
                    .verify(signing_bytes, &signature)
                    .map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::EdBlake2b => {
                todo!()
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_curve25519() -> Self {
        Self::EdDsa(EdDsaSecretKey::generate_ed25519())
    }

    pub fn generate_curve25519_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::EdDsa(EdDsaSecretKey::generate_ed25519_from(rng))
    }

    pub fn new_curve25519(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        EdDsaSecretKey::new_ed25519(bytes).map(Self::EdDsa)
    }
}

impl EdDsaSecretKey {
    pub fn generate_ed25519() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_ed25519_from(&mut rng)
    }

    pub fn generate_ed25519_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Curve25519(ed25519_dalek::SigningKey::generate(rng))
    }

    pub fn new_ed25519(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        bytes
            .try_into()
            .map(Self::Curve25519)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for Ed25519SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        use ed25519_dalek::Signer;
        match algorithm.into() {
            AlgorithmInstance::EdDsa => Ok(self.sign(signing_bytes).to_bytes().into()),
            AlgorithmInstance::EdBlake2b => {
                use blake2::digest::{consts::U32, Digest};
                use ed25519_dalek::Signer;

                let hash = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes).finalize();

                // TODO this was copied from old code, but the `sign` method is
                // probably going to use SHA-256 on top of `hash`, which is
                // already digested with blake2. We should check if this is the
                // intended behavior.
                Ok(self.sign(&hash).to_bytes().into())
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
