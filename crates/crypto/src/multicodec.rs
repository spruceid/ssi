use ssi_multicodec::{MultiEncoded, MultiEncodedBuf};

use crate::{key::KeyConversionError, PublicKey};

impl PublicKey {
    pub fn from_multicodec(multicodec: &MultiEncoded) -> Result<Self, KeyConversionError> {
        #[allow(unused_variables)]
        let (codec, k) = multicodec.parts();
        match codec {
            #[cfg(feature = "rsa")]
            ssi_multicodec::RSA_PUB => Self::from_rsa_pkcs1_der(k),
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => Self::from_ed25519_bytes(k),
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => Self::from_ecdsa_k256_sec1_bytes(k),
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => Self::from_ecdsa_p256_sec1_bytes(k),
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => Self::from_ecdsa_p384_sec1_bytes(k),
            // #[cfg(feature = "bbs")]
            // ssi_multicodec::BLS12_381_G2_PUB => Self::from_public_bls12381g2_bytes(k),
            _ => Err(KeyConversionError::Unsupported),
        }
    }

    pub fn to_multicodec(&self) -> Result<MultiEncodedBuf, KeyConversionError> {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(key) => {
                use rsa::pkcs1::EncodeRsaPublicKey;
                Ok(MultiEncodedBuf::encode_bytes(
                    ssi_multicodec::RSA_PUB,
                    key.to_pkcs1_der()
                        .map_err(|_| KeyConversionError::Invalid)?,
                ))
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => Ok(MultiEncodedBuf::encode_bytes(
                ssi_multicodec::ED25519_PUB,
                key.to_bytes(),
            )),
            #[cfg(feature = "secp256k1")]
            Self::K256(key) => Ok(MultiEncodedBuf::encode_bytes(
                ssi_multicodec::SECP256K1_PUB,
                key.to_sec1_bytes(),
            )),
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => Ok(MultiEncodedBuf::encode_bytes(
                ssi_multicodec::P256_PUB,
                key.to_sec1_bytes(),
            )),
            #[cfg(feature = "secp384r1")]
            Self::P384(key) => Ok(MultiEncodedBuf::encode_bytes(
                ssi_multicodec::P384_PUB,
                key.to_sec1_bytes(),
            )),
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}
