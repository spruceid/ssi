use crate::AlgorithmInstance;

pub trait RecoverableKey: Sized {
    fn recover_from(
        algorithm: &AlgorithmInstance,
        signature_bytes: &[u8],
    ) -> Result<Self, RecoveringError>;
}

pub struct RecoveringError;

// /// Recover a key from a signature and message, if the algorithm supports this.  (e.g.
// /// [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r))
// pub fn recover(algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<JWK, Error> {
//     match algorithm {
//         #[cfg(feature = "secp256k1")]
//         Algorithm::ES256KR => {
//             use k256::ecdsa::VerifyingKey;
//             if signature.len() != 65 {
//                 Err(k256::ecdsa::Error::new())?;
//             }
//             let sig =
//                 k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
//             let rec_id =
//                 k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
//             let hash = ssi_crypto::hashes::sha256::sha256(data);
//             let digest = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::from_slice(&hash);
//             let recovered_key = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
//                 .map_err(ssi_jwk::Error::from)?;
//             use ssi_jwk::EcParams;
//             let jwk = JWK {
//                 params: JWKParams::Ec(EcParams::from(
//                     &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
//                         .map_err(ssi_jwk::Error::from)?,
//                 )),
//                 public_key_use: None,
//                 key_operations: None,
//                 algorithm: None,
//                 key_id: None,
//                 x509_url: None,
//                 x509_certificate_chain: None,
//                 x509_thumbprint_sha1: None,
//                 x509_thumbprint_sha256: None,
//             };
//             Ok(jwk)
//         }
//         #[cfg(feature = "secp256k1")]
//         Algorithm::ESKeccakKR => {
//             use k256::ecdsa::{signature::digest::Digest, VerifyingKey};
//             if signature.len() != 65 {
//                 Err(k256::ecdsa::Error::new())?;
//             }
//             let sig =
//                 k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
//             let rec_id =
//                 k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
//             let recovered_key = VerifyingKey::recover_from_digest(
//                 sha3::Keccak256::new_with_prefix(data),
//                 &sig,
//                 rec_id,
//             )
//             .map_err(ssi_jwk::Error::from)?;
//             use ssi_jwk::EcParams;
//             let jwk = JWK::from(JWKParams::Ec(EcParams::from(
//                 &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
//                     .map_err(ssi_jwk::Error::from)?,
//             )));
//             Ok(jwk)
//         }
//         _ => {
//             let _ = data;
//             let _ = signature;
//             Err(Error::UnsupportedAlgorithm(algorithm.to_string()))
//         }
//     }
// }
