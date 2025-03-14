use crate::{hashes, AlgorithmInstance, SignatureError, SigningKey, VerifyingKey};
use rsa::PaddingScheme;
pub use rsa::{RsaPrivateKey as RsaSecretKey, RsaPublicKey};

impl VerifyingKey for RsaPublicKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::Verification, crate::VerificationError> {
        todo!()
    }
}

impl SigningKey for RsaSecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        match algorithm.into() {
            AlgorithmInstance::RS256 => {
                let hash = rsa::Hash::SHA2_256;
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(hash));
                let digest_in = hashes::sha256::sha256(signing_bytes);
                self.sign(padding, &digest_in)
                    .map(Vec::into_boxed_slice)
                    .map_err(SignatureError::other)
            }
            AlgorithmInstance::PS256 => {
                let hash = rsa::Hash::SHA2_256;
                let rng = rand::rngs::OsRng {};
                let padding = PaddingScheme::new_pss_with_salt::<sha2::Sha256, _>(rng, hash.size());
                let digest_in = hashes::sha256::sha256(signing_bytes);
                self.sign(padding, &digest_in)
                    .map(Vec::into_boxed_slice)
                    .map_err(SignatureError::other)
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
