impl PublicKey {
    pub fn new_p384(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        p384::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P384)
            .map_err(|_| InvalidPublicKey)
    }
}

impl VerifyingKey for P384PublicKey {
    fn verify_bytes(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<crate::Verification, crate::VerificationError> {
        match algorithm {
            AlgorithmInstance::ES384 => {
                // use p384::ecdsa::signature::Verifier;
                // let verifying_key = p384::ecdsa::VerifyingKey::from(key);
                // let sig = p384::ecdsa::Signature::try_from(signature_bytes)
                // 	.map_err(|_| VerificationError::MalformedSignature)?;
                // Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                todo!()
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_p384() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p384_from(&mut rng)
    }

    pub fn generate_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P384(p384::SecretKey::random(rng))
    }

    pub fn new_p384(d: &[u8]) -> Result<Self, InvalidSecretKey> {
        p384::SecretKey::from_bytes(d.into())
            .map(Self::P384)
            .map_err(|_| InvalidSecretKey)
    }
}

impl SigningKey for P384SecretKey {
    fn sign_bytes(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        match algorithm {
            AlgorithmInstance::ES384 => {
                use p384::ecdsa::{signature::Signer, Signature};
                let signing_key = p384::ecdsa::SigningKey::from(key);
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-384 by default.
                Ok(signature.to_bytes().to_vec())
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
