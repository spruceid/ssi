use ssi_crypto::key::KeyConversionError;
use ssi_multicodec::{Codec, MultiEncoded, MultiEncodedBuf};
use std::borrow::Cow;

use crate::{Params, JWK};

impl JWK {
    pub fn from_multicodec(multicodec: &MultiEncoded) -> Result<Self, KeyConversionError> {
        #[allow(unused_variables)]
        let (codec, k) = multicodec.parts();
        match codec {
            #[cfg(feature = "rsa")]
            ssi_multicodec::RSA_PUB => Self::from_rsa_public_pkcs1_der_bytes(k),
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => Self::from_public_ed25519_bytes(k),
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PRIV => Self::from_secret_ed25519_bytes(k),
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => Self::from_public_k256_bytes(k),
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PRIV => Self::from_secret_k256_bytes(k),
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => Self::from_public_p256_bytes(k),
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PRIV => Self::from_secret_p256_bytes(k),
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => Self::from_public_p384_bytes(k),
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PRIV => Self::from_secret_p384_bytes(k),
            #[cfg(feature = "bbs")]
            ssi_multicodec::BLS12_381_G2_PUB => Self::from_public_bls12381g2_bytes(k),
            ssi_multicodec::JWK_JCS_PUB => {
                JWK::from_bytes(k).map_err(|_| KeyConversionError::Invalid)
            }
            _ => Err(KeyConversionError::Unsupported),
        }
    }

    pub fn to_multicodec(&self) -> Result<MultiEncodedBuf, KeyConversionError> {
        match self.params {
            Params::Okp(ref params) => match &params.curve[..] {
                "Ed25519" => Ok(MultiEncodedBuf::encode_bytes(
                    ssi_multicodec::ED25519_PUB,
                    &params.public_key.0,
                )),
                _ => Err(KeyConversionError::Unsupported),
            },
            Params::Ec(ref params) => {
                let curve = match params.curve {
                    Some(ref curve) => curve,
                    None => return Err(KeyConversionError::Invalid),
                };

                match curve.as_str() {
                    #[cfg(feature = "secp256k1")]
                    "secp256k1" => {
                        use ssi_crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = ssi_crypto::k256::PublicKey::try_from(params)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::SECP256K1_PUB,
                            pk.to_encoded_point(true).as_bytes(),
                        ))
                    }
                    #[cfg(feature = "secp256r1")]
                    "P-256" => {
                        use ssi_crypto::p256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = ssi_crypto::p256::PublicKey::try_from(params)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::P256_PUB,
                            pk.to_encoded_point(true).as_bytes(),
                        ))
                    }
                    #[cfg(feature = "secp384r1")]
                    "P-384" => {
                        let pk_bytes = params.to_public_p384_bytes()?;
                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::P384_PUB,
                            &pk_bytes,
                        ))
                    }
                    #[cfg(feature = "bbs")]
                    "BLS12381G2" => {
                        let pk: ssi_bbs::BBSplusPublicKey = self.try_into()?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::BLS12_381_G2_PUB,
                            &pk.to_bytes(),
                        ))
                    }
                    _ => Err(KeyConversionError::Unsupported),
                }
            }
            #[cfg(feature = "rsa")]
            Params::Rsa(ref params) => {
                let der = params.to_rsa_public_pkcs1_der_bytes()?;
                Ok(MultiEncodedBuf::encode_bytes(ssi_multicodec::RSA_PUB, &der))
            }
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

impl Codec for JWK {
    const CODEC: u64 = ssi_multicodec::JWK_JCS_PUB;

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_jcs::to_vec(self).unwrap())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ssi_multicodec::Error> {
        Self::try_from(bytes).map_err(|_| ssi_multicodec::Error::InvalidData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "secp256r1")]
    fn test_multicodec_jwk_jcs_pub() {
        let jwk = JWK::generate_p256();
        // Note: can't use JWK::to_multicodec() because it's based on the particular key within the JWK
        // it will see the P256 key and assign a multicodec of 0x1200.
        // For jwk_jcs_pub multicodecs, we can only decode them
        let jwk_buf = MultiEncodedBuf::encode(&jwk);
        let (codec, data) = jwk_buf.parts();
        assert_eq!(codec, ssi_multicodec::JWK_JCS_PUB);
        assert_eq!(*data, jwk.to_bytes().into_owned());
        let jwk2 = JWK::from_multicodec(&jwk_buf).unwrap();
        assert_eq!(jwk, jwk2);
    }
}
