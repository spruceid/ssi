use coset::{
    iana::{self, EnumI64},
    CoseKey, KeyType, Label,
};
use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_crypto::{
    rand::{CryptoRng, RngCore},
    PublicKey, SecretKey,
};
use std::borrow::Cow;

use crate::{
    algorithm::{algorithm_name, instantiate_algorithm, preferred_algorithm},
    CoseSigner, CoseSignerInfo,
};

/// COSE key resolver.
pub trait CoseKeyResolver {
    /// Fetches the COSE key associated to the give identifier.
    #[allow(async_fn_in_trait)]
    async fn fetch_public_cose_key(
        &self,
        id: Option<&[u8]>,
    ) -> Result<Cow<CoseKey>, ProofValidationError>;
}

impl<'a, T: CoseKeyResolver> CoseKeyResolver for &'a T {
    async fn fetch_public_cose_key(
        &self,
        id: Option<&[u8]>,
    ) -> Result<Cow<CoseKey>, ProofValidationError> {
        T::fetch_public_cose_key(*self, id).await
    }
}

impl CoseKeyResolver for CoseKey {
    async fn fetch_public_cose_key(
        &self,
        _id: Option<&[u8]>,
    ) -> Result<Cow<CoseKey>, ProofValidationError> {
        Ok(Cow::Borrowed(self))
    }
}

impl CoseSigner for CoseKey {
    async fn fetch_info(&self) -> Result<CoseSignerInfo, ssi_claims_core::SignatureError> {
        Ok(CoseSignerInfo {
            algorithm: preferred_algorithm(self).map(Cow::into_owned),
            key_id: self.key_id.clone(),
        })
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let algorithm = preferred_algorithm(self).ok_or(SignatureError::MissingAlgorithm)?;
        let secret_key = self.decode_secret()?;
        secret_key
            .sign(
                instantiate_algorithm(&algorithm).ok_or_else(|| {
                    SignatureError::UnsupportedAlgorithm(algorithm_name(&algorithm))
                })?,
                signing_bytes,
            )
            .map_err(Into::into)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyDecodingError {
    #[error("unsupported key type")]
    UnsupportedKeyType(KeyType),

    #[error("missing parameter")]
    MissingParam(Label),

    #[error("invalid parameter")]
    InvalidParam(Label),

    #[error("unsupported parameter value")]
    UnsupportedParam(Label, ciborium::Value),

    #[error("invalid key")]
    InvalidKey,
}

impl From<ssi_crypto::key::InvalidPublicKey> for KeyDecodingError {
    fn from(_value: ssi_crypto::key::InvalidPublicKey) -> Self {
        Self::InvalidKey
    }
}

impl From<ssi_crypto::key::InvalidSecretKey> for KeyDecodingError {
    fn from(_value: ssi_crypto::key::InvalidSecretKey) -> Self {
        Self::InvalidKey
    }
}

impl From<KeyDecodingError> for ssi_claims_core::SignatureError {
    fn from(_value: KeyDecodingError) -> Self {
        Self::InvalidSecretKey
    }
}

/// Decode COSE keys.
pub trait CoseKeyDecode {
    fn fetch_param(&self, label: &Label) -> Option<&ciborium::Value>;

    fn require_param(&self, label: &Label) -> Result<&ciborium::Value, KeyDecodingError> {
        self.fetch_param(label)
            .ok_or_else(|| KeyDecodingError::MissingParam(label.clone()))
    }

    fn parse_required_param<'a, T>(
        &'a self,
        label: &Label,
        f: impl FnOnce(&'a ciborium::Value) -> Option<T>,
    ) -> Result<T, KeyDecodingError> {
        f(self.require_param(label)?).ok_or_else(|| KeyDecodingError::InvalidParam(label.clone()))
    }

    /// Decodes the COSE key as a public key.
    fn decode_public(&self) -> Result<ssi_crypto::PublicKey, KeyDecodingError>;

    /// Decodes the COSE key as a secret key.
    fn decode_secret(&self) -> Result<ssi_crypto::SecretKey, KeyDecodingError>;
}

impl CoseKeyDecode for CoseKey {
    /// Fetch a key parameter.
    fn fetch_param(&self, label: &Label) -> Option<&ciborium::Value> {
        self.params
            .iter()
            .find_map(|(l, value)| if l == label { Some(value) } else { None })
    }

    fn decode_public(&self) -> Result<ssi_crypto::PublicKey, KeyDecodingError> {
        match &self.kty {
            t @ KeyType::Assigned(kty) => {
                match kty {
                    // Octet Key Pair.
                    iana::KeyType::OKP => {
                        let crv = self.parse_required_param(&OKP_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let x = self.parse_required_param(&OKP_X, ciborium::Value::as_bytes)?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "ed25519")]
                            Some(iana::EllipticCurve::Ed25519) => {
                                ssi_crypto::PublicKey::new_ed25519(x).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    // Double Coordinate Curves.
                    // See: <https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1>
                    iana::KeyType::EC2 => {
                        let crv = self.parse_required_param(&EC2_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let x = self.parse_required_param(&EC2_X, ciborium::Value::as_bytes)?;

                        #[allow(unused_variables)]
                        let y = self.parse_required_param(
                            &EC2_Y,
                            ciborium::Value::as_bytes, // TODO: this can be a `bool`
                        )?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "secp256k1")]
                            Some(iana::EllipticCurve::Secp256k1) => {
                                ssi_crypto::PublicKey::new_secp256k1(x, y).map_err(Into::into)
                            }
                            #[cfg(feature = "secp256r1")]
                            Some(iana::EllipticCurve::P_256) => {
                                ssi_crypto::PublicKey::new_p256(x, y).map_err(Into::into)
                            }
                            #[cfg(feature = "secp384r1")]
                            Some(iana::EllipticCurve::P_384) => {
                                ssi_crypto::PublicKey::new_p384(x, y).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    _ => Err(KeyDecodingError::UnsupportedKeyType(t.clone())),
                }
            }
            other => Err(KeyDecodingError::UnsupportedKeyType(other.clone())),
        }
    }

    fn decode_secret(&self) -> Result<ssi_crypto::SecretKey, KeyDecodingError> {
        match &self.kty {
            t @ KeyType::Assigned(kty) => {
                match kty {
                    // Octet Key Pair.
                    iana::KeyType::OKP => {
                        let crv = self.parse_required_param(&OKP_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let d = self.parse_required_param(&OKP_X, ciborium::Value::as_bytes)?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "ed25519")]
                            Some(iana::EllipticCurve::Ed25519) => {
                                ssi_crypto::SecretKey::new_ed25519(d).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    // Double Coordinate Curves.
                    // See: <https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1>
                    iana::KeyType::EC2 => {
                        let crv = self.parse_required_param(&EC2_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let d = self.parse_required_param(&EC2_D, ciborium::Value::as_bytes)?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "secp256k1")]
                            Some(iana::EllipticCurve::Secp256k1) => {
                                ssi_crypto::SecretKey::new_secp256k1(d).map_err(Into::into)
                            }
                            #[cfg(feature = "secp256r1")]
                            Some(iana::EllipticCurve::P_256) => {
                                ssi_crypto::SecretKey::new_p256(d).map_err(Into::into)
                            }
                            #[cfg(feature = "secp384r1")]
                            Some(iana::EllipticCurve::P_384) => {
                                ssi_crypto::SecretKey::new_p384(d).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    _ => Err(KeyDecodingError::UnsupportedKeyType(t.clone())),
                }
            }
            other => Err(KeyDecodingError::UnsupportedKeyType(other.clone())),
        }
    }
}

pub const OKP_CRV: Label = Label::Int(iana::OkpKeyParameter::Crv as i64);
pub const OKP_X: Label = Label::Int(iana::OkpKeyParameter::X as i64);
pub const OKP_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);

pub const EC2_CRV: Label = Label::Int(iana::Ec2KeyParameter::Crv as i64);
pub const EC2_X: Label = Label::Int(iana::Ec2KeyParameter::X as i64);
pub const EC2_Y: Label = Label::Int(iana::Ec2KeyParameter::Y as i64);
pub const EC2_D: Label = Label::Int(iana::Ec2KeyParameter::D as i64);

#[derive(Debug, thiserror::Error)]
pub enum KeyEncodingError {
    #[error("unsupported key type")]
    UnsupportedKeyType,
}

/// COSE key encoding
pub trait CoseKeyEncode: Sized {
    fn encode_public(key: &PublicKey) -> Result<Self, KeyEncodingError>;

    fn encode_secret(key: &SecretKey) -> Result<Self, KeyEncodingError>;
}

impl CoseKeyEncode for CoseKey {
    fn encode_public(key: &PublicKey) -> Result<Self, KeyEncodingError> {
        match key {
            #[cfg(feature = "secp256k1")]
            PublicKey::Secp256k1(key) => {
                use ssi_crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::Secp256k1.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp256r1")]
            PublicKey::P256(key) => {
                use ssi_crypto::p256::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_256.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp384r1")]
            PublicKey::P384(key) => {
                use ssi_crypto::p384::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_384.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            _ => Err(KeyEncodingError::UnsupportedKeyType),
        }
    }

    fn encode_secret(key: &SecretKey) -> Result<Self, KeyEncodingError> {
        match key {
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(key) => {
                use ssi_crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
                let public_key = key.public_key();
                let encoded_point = public_key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::Secp256k1.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                        (EC2_D, key.to_bytes().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp256r1")]
            SecretKey::P256(key) => {
                use ssi_crypto::p256::elliptic_curve::sec1::ToEncodedPoint;
                let public_key = key.public_key();
                let encoded_point = public_key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_256.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                        (EC2_D, key.to_bytes().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp384r1")]
            SecretKey::P384(key) => {
                use ssi_crypto::p384::elliptic_curve::sec1::ToEncodedPoint;
                let public_key = key.public_key();
                let encoded_point = public_key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_384.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                        (EC2_D, key.to_bytes().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            _ => Err(KeyEncodingError::UnsupportedKeyType),
        }
    }
}

pub trait CoseKeyGenerate {
    #[cfg(feature = "ed25519")]
    fn generate_ed25519() -> Self;

    #[cfg(feature = "ed25519")]
    fn generate_ed25519_from(rng: &mut (impl RngCore + CryptoRng)) -> Self;

    #[cfg(feature = "secp256k1")]
    fn generate_secp256k1() -> Self;

    #[cfg(feature = "secp256k1")]
    fn generate_secp256k1_from(rng: &mut (impl RngCore + CryptoRng)) -> Self;

    #[cfg(feature = "secp256r1")]
    fn generate_p256() -> Self;

    #[cfg(feature = "secp256r1")]
    fn generate_p256_from(rng: &mut (impl RngCore + CryptoRng)) -> Self;

    #[cfg(feature = "secp384r1")]
    fn generate_p384() -> Self;

    #[cfg(feature = "secp384r1")]
    fn generate_p384_from(rng: &mut (impl RngCore + CryptoRng)) -> Self;
}

impl CoseKeyGenerate for CoseKey {
    #[cfg(feature = "ed25519")]
    fn generate_ed25519() -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_ed25519()).unwrap()
    }

    #[cfg(feature = "ed25519")]
    fn generate_ed25519_from(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_ed25519_from(rng)).unwrap()
    }

    #[cfg(feature = "secp256k1")]
    fn generate_secp256k1() -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_secp256k1()).unwrap()
    }

    #[cfg(feature = "secp256k1")]
    fn generate_secp256k1_from(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_secp256k1_from(rng)).unwrap()
    }

    #[cfg(feature = "secp256r1")]
    fn generate_p256() -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_p256()).unwrap()
    }

    #[cfg(feature = "secp256r1")]
    fn generate_p256_from(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_p256_from(rng)).unwrap()
    }

    #[cfg(feature = "secp384r1")]
    fn generate_p384() -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_p384()).unwrap()
    }

    #[cfg(feature = "secp384r1")]
    fn generate_p384_from(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::encode_secret(&ssi_crypto::SecretKey::generate_p384_from(rng)).unwrap()
    }
}
