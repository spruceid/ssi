use crate::{
    key::KeyConversionError, AlgorithmInstance, PublicKey, SecretKey, SignatureError, SigningKey,
    Verification, VerificationError, VerifyingKey,
};
pub use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};

impl PublicKey {
    pub fn from_ed25519_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        bytes
            .try_into()
            .map(Self::Ed25519)
            .map_err(|_| KeyConversionError::Invalid)
    }

    pub fn new_ed25519(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        bytes
            .try_into()
            .map(Self::Ed25519)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for Ed25519PublicKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError> {
        match algorithm.into() {
            AlgorithmInstance::EdDsa => {
                // use ed25519_dalek::Verifier;
                // let signature: ed25519_dalek::Signature = signature_bytes
                //     .try_into()
                //     .map_err(|_| VerificationError::MalformedSignature)?;
                // Ok(key.verify(signing_bytes, &signature).is_ok())
                todo!()
            }
            AlgorithmInstance::EdBlake2b => {
                todo!()
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_ed25519() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_ed25519_from(&mut rng)
    }

    pub fn generate_ed25519_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::generate(rng))
    }

    pub fn new_ed25519(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        bytes
            .try_into()
            .map(Self::Ed25519)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for Ed25519SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        use ed25519_dalek::Signer;
        match algorithm.into() {
            AlgorithmInstance::EdDsa => Ok(self.sign(signing_bytes).to_bytes().into()),
            AlgorithmInstance::EdBlake2b => {
                use blake2::digest::{consts::U32, Digest};
                use ed25519_dalek::Signer;

                let hash = blake2::Blake2b::<U32>::new_with_prefix(signing_bytes).finalize();

                // TODO this was copied from old code, but the `sign` method is
                // probably going to use SHA-256 on top of `hash`, which is
                // already digested with blake2. We should check is this is the
                // intended behavior.
                Ok(self.sign(&hash).to_bytes().into())
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
