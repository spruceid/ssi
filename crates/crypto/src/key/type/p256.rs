use crate::{
    key::KeyConversionError, AlgorithmInstance, PublicKey, SecretKey, SignatureError, SigningKey,
    VerificationError, VerifyingKey,
};
pub use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};

impl PublicKey {
    pub fn new_p256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        P256PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for P256PublicKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::Verification, crate::VerificationError> {
        match algorithm.into() {
            AlgorithmInstance::ES256 => {
                // use p256::ecdsa::signature::Verifier;
                // let verifying_key = p256::ecdsa::VerifyingKey::from(key);
                // let sig = p256::ecdsa::Signature::try_from(signature_bytes)
                // 	.map_err(|_| VerificationError::MalformedSignature)?;
                // Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                todo!()
            }
            AlgorithmInstance::ESBlake2b => {
                todo!()
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_p256() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p256_from(&mut rng)
    }

    pub fn generate_p256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P256(P256SecretKey::random(rng))
    }

    pub fn new_p256(d: &[u8]) -> Result<Self, KeyConversionError> {
        p256::SecretKey::from_bytes(d.into())
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for P256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        match algorithm.into() {
            AlgorithmInstance::ES256 => {
                use p256::ecdsa::{signature::Signer, Signature};
                let signing_key = p256::ecdsa::SigningKey::from(self);
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().as_slice().into())
            }
            AlgorithmInstance::ESBlake2b => {
                todo!()
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
