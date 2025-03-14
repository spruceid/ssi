use crate::{
    key::KeyConversionError, AlgorithmInstance, PublicKey, SecretKey, SignatureError, SigningKey,
    VerificationError, VerifyingKey,
};
pub use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};

impl PublicKey {
    pub fn new_secp256k1(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        k256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for K256PublicKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::Verification, crate::VerificationError> {
        match algorithm.into() {
            AlgorithmInstance::ES256K => {
                // use k256::ecdsa::signature::Verifier;
                // let verifying_key = k256::ecdsa::VerifyingKey::from(key);
                // let sig = k256::ecdsa::Signature::try_from(signature_bytes)
                //     .map_err(|_| VerificationError::MalformedSignature)?;
                // Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                todo!()
            }
            AlgorithmInstance::ES256KR => {
                todo!()
            }
            AlgorithmInstance::ESBlake2bK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakKR => {
                todo!()
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_secp256k1() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_secp256k1_from(&mut rng)
    }

    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::K256(k256::SecretKey::random(rng))
    }

    pub fn new_secp256k1(d: &[u8]) -> Result<Self, KeyConversionError> {
        k256::SecretKey::from_bytes(d.into())
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for K256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing_key = SigningKey::from(self);

        match algorithm.into() {
            AlgorithmInstance::ES256K => {
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().to_vec().into_boxed_slice())
            }
            AlgorithmInstance::ES256KR => {
                todo!()
            }
            AlgorithmInstance::ESBlake2bK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakKR => {
                todo!()
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
