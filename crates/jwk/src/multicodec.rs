use ssi_multicodec::{Codec, MultiEncoded, MultiEncodedBuf};
use std::borrow::Cow;

use crate::{Error, Params, JWK};

impl JWK {
    pub fn from_multicodec(multicodec: &MultiEncoded) -> Result<Self, FromMulticodecError> {
        #[allow(unused_variables)]
        let (codec, k) = multicodec.parts();
        match codec {
            #[cfg(feature = "rsa")]
            ssi_multicodec::RSA_PUB => {
                crate::rsa_x509_pub_parse(k).map_err(FromMulticodecError::RsaPub)
            }
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => {
                crate::ed25519_parse(k).map_err(FromMulticodecError::Ed25519Pub)
            }
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PRIV => {
                crate::ed25519_parse_private(k).map_err(FromMulticodecError::Ed25519Priv)
            }
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => {
                crate::secp256k1_parse(k).map_err(FromMulticodecError::Secp256k1Pub)
            }
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PRIV => {
                crate::secp256k1_parse_private(k).map_err(FromMulticodecError::Secp256k1Priv)
            }
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => {
                crate::p256_parse(k).map_err(FromMulticodecError::Secp256r1Pub)
            }
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PRIV => {
                crate::p256_parse_private(k).map_err(FromMulticodecError::Secp256r1Priv)
            }
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => {
                crate::p384_parse(k).map_err(FromMulticodecError::Secp384r1Pub)
            }
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PRIV => {
                crate::p384_parse_private(k).map_err(FromMulticodecError::Secp384r1Priv)
            }
            #[cfg(feature = "bbs")]
            ssi_multicodec::BLS12_381_G2_PUB => {
                crate::bls12381g2_parse(k).map_err(FromMulticodecError::Bls12381G2Pub)
            }
            ssi_multicodec::JWK_JCS_PUB => {
                JWK::from_bytes(k).map_err(FromMulticodecError::JwkJcsPub)
            }
            _ => Err(FromMulticodecError::UnsupportedCodec(codec)),
        }
    }

    pub fn to_multicodec(&self) -> Result<MultiEncodedBuf, ToMulticodecError> {
        match self.params {
            Params::OKP(ref params) => match &params.curve[..] {
                "Ed25519" => Ok(MultiEncodedBuf::encode_bytes(
                    ssi_multicodec::ED25519_PUB,
                    &params.public_key.0,
                )),
                _ => Err(ToMulticodecError::UnsupportedCurve(params.curve.clone())),
            },
            Params::EC(ref params) => {
                let curve = match params.curve {
                    Some(ref curve) => curve,
                    None => return Err(ToMulticodecError::MissingCurve),
                };

                match curve.as_str() {
                    #[cfg(feature = "secp256k1")]
                    "secp256k1" => {
                        use k256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = k256::PublicKey::try_from(params)
                            .map_err(ToMulticodecError::InvalidInputKey)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::SECP256K1_PUB,
                            pk.to_encoded_point(true).as_bytes(),
                        ))
                    }
                    #[cfg(feature = "secp256r1")]
                    "P-256" => {
                        use p256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = p256::PublicKey::try_from(params)
                            .map_err(ToMulticodecError::InvalidInputKey)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::P256_PUB,
                            pk.to_encoded_point(true).as_bytes(),
                        ))
                    }
                    #[cfg(feature = "secp384r1")]
                    "P-384" => {
                        let pk_bytes = crate::serialize_p384(params)
                            .map_err(ToMulticodecError::InvalidInputKey)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::P384_PUB,
                            &pk_bytes,
                        ))
                    }
                    #[cfg(feature = "bbs")]
                    "BLS12381G2" => {
                        let pk: ssi_bbs::BBSplusPublicKey = self
                            .try_into()
                            .map_err(ToMulticodecError::InvalidInputKey)?;

                        Ok(MultiEncodedBuf::encode_bytes(
                            ssi_multicodec::BLS12_381_G2_PUB,
                            &pk.to_bytes(),
                        ))
                    }
                    _ => Err(ToMulticodecError::UnsupportedCurve(curve.to_owned())),
                }
            }
            Params::RSA(ref params) => {
                let der = simple_asn1::der_encode(&params.to_public())
                    .map_err(ToMulticodecError::InvalidInputKey)?;
                Ok(MultiEncodedBuf::encode_bytes(ssi_multicodec::RSA_PUB, &der))
            }
            _ => Err(ToMulticodecError::UnsupportedKeyType),
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

#[derive(Debug, thiserror::Error)]
pub enum FromMulticodecError {
    #[cfg(feature = "rsa")]
    #[error(transparent)]
    RsaPub(crate::RsaX509PubParseError),

    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Ed25519Pub(Error),

    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Ed25519Priv(Error),

    #[cfg(feature = "secp256k1")]
    #[error(transparent)]
    Secp256k1Pub(Error),

    #[cfg(feature = "secp256k1")]
    #[error(transparent)]
    Secp256k1Priv(Error),

    #[cfg(feature = "secp256r1")]
    #[error(transparent)]
    Secp256r1Pub(Error),

    #[cfg(feature = "secp256r1")]
    #[error(transparent)]
    Secp256r1Priv(Error),

    #[cfg(feature = "secp384r1")]
    #[error(transparent)]
    Secp384r1Pub(Error),

    #[cfg(feature = "secp384r1")]
    #[error(transparent)]
    Secp384r1Priv(Error),

    #[cfg(feature = "bbs")]
    #[error(transparent)]
    Bls12381G2Pub(ssi_bbs::Error),

    #[error(transparent)]
    JwkJcsPub(ssi_multicodec::Error),

    /// Unexpected multibase (multicodec) key prefix multicodec
    #[error("Unsupported multicodec key type 0x{0:x}")]
    UnsupportedCodec(u64),
}

#[derive(Debug, thiserror::Error)]
pub enum ToMulticodecError {
    #[error("unsupported key type")]
    UnsupportedKeyType,

    #[error("unsupported curve `{0}`")]
    UnsupportedCurve(String),

    #[error("missing curve")]
    MissingCurve,

    #[error("invalid input key: {0}")]
    InvalidInputKey(Error),
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
