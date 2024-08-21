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
    /// Reads a key parameter, if it exists.
    fn fetch_param(&self, label: &Label) -> Option<&ciborium::Value>;

    /// Requires the given key parameter.
    ///
    /// Returns an error if the key parameter is not present in the key.
    fn require_param(&self, label: &Label) -> Result<&ciborium::Value, KeyDecodingError> {
        self.fetch_param(label)
            .ok_or_else(|| KeyDecodingError::MissingParam(label.clone()))
    }

    /// Requires and parses the given key parameter.
    ///
    /// Returns an error if the key parameter is not present in the key, or
    /// if the parsing function `f` returns `None`.
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
                        let d = self.parse_required_param(&OKP_D, ciborium::Value::as_bytes)?;

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
    fn encode_public(key: &PublicKey) -> Result<CoseKey, KeyEncodingError>;

    fn encode_public_with_id(key: &PublicKey, id: Vec<u8>) -> Result<CoseKey, KeyEncodingError> {
        let mut cose_key = Self::encode_public(key)?;
        cose_key.key_id = id;
        Ok(cose_key)
    }

    fn encode_secret(key: &SecretKey) -> Result<CoseKey, KeyEncodingError>;

    fn encode_secret_with_id(key: &SecretKey, id: Vec<u8>) -> Result<CoseKey, KeyEncodingError> {
        let mut cose_key = Self::encode_secret(key)?;
        cose_key.key_id = id;
        Ok(cose_key)
    }
}

impl CoseKeyEncode for CoseKey {
    fn encode_public(key: &PublicKey) -> Result<Self, KeyEncodingError> {
        match key {
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(key) => Ok(Self {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                params: vec![
                    (OKP_CRV, iana::EllipticCurve::Ed25519.to_i64().into()),
                    (OKP_X, key.as_bytes().to_vec().into()),
                ],
                ..Default::default()
            }),
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
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(key) => {
                let public_key = key.verifying_key();
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::OKP),
                    params: vec![
                        (OKP_CRV, iana::EllipticCurve::Ed25519.to_i64().into()),
                        (OKP_X, public_key.as_bytes().to_vec().into()),
                        (OKP_D, key.to_bytes().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
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

#[cfg(test)]
mod tests {
    use super::{CoseKeyDecode, CoseKeyEncode};
    use coset::{CborSerializable, CoseKey};
    use ssi_crypto::{PublicKey, SecretKey};

    /// Public secp256k1 key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 1,
    ///   -1: 6,
    ///   -2: h'8816d41001dd1a9ddea1232381b2eede803161e88ebb19eaf573d393dec800a7'
    /// }
    /// ```
    #[cfg(feature = "ed25519")]
    #[test]
    fn public_ed25519_1() {
        let input = hex::decode(
            "a3010120062158208816d41001dd1a9ddea1232381b2eede803161e88ebb19eaf573d393dec800a7",
        )
        .unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::Ed25519(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// Secret secp256k1 key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 1,
    ///   -1: 6,
    ///   -2: h'8816d41001dd1a9ddea1232381b2eede803161e88ebb19eaf573d393dec800a7',
    ///   -4: h'e25df1249ab766fc5a8c9f98d5e311cd4f7d5fd1c6b6a2032adc973056c87dc3'
    /// }
    /// ```
    #[cfg(feature = "ed25519")]
    #[test]
    fn secret_ed25519_1() {
        let input = hex::decode("a4010120062158208816d41001dd1a9ddea1232381b2eede803161e88ebb19eaf573d393dec800a7235820e25df1249ab766fc5a8c9f98d5e311cd4f7d5fd1c6b6a2032adc973056c87dc3").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::Ed25519(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// Secret secp256k1 key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 2,
    ///   -1: 8,
    ///   -2: h'394fd5a1e33b8a67d5fa9ddca42d261219dde202e65bbf07bf2f671e157ac41f',
    ///   -3: h'199d7db667e74905c8371168b815c267db76243fbfd387fa5f2d8a691099a89a'
    /// }
    /// ```
    #[cfg(feature = "secp256k1")]
    #[test]
    fn public_secp256k1_1() {
        let input = hex::decode("a401022008215820394fd5a1e33b8a67d5fa9ddca42d261219dde202e65bbf07bf2f671e157ac41f225820199d7db667e74905c8371168b815c267db76243fbfd387fa5f2d8a691099a89a").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::Secp256k1(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// Secret secp256k1 key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 2,
    ///   -1: 8,
    ///   -2: h'394fd5a1e33b8a67d5fa9ddca42d261219dde202e65bbf07bf2f671e157ac41f',
    ///   -3: h'199d7db667e74905c8371168b815c267db76243fbfd387fa5f2d8a691099a89a',
    ///   -4: h'3e0fada8be75e5e47ab4c1c91c3f8f9185d1e18a2a16b3400a1eb33c9cdf8b96'
    /// }
    /// ```
    #[cfg(feature = "secp256k1")]
    #[test]
    fn secret_secp256k1_1() {
        let input = hex::decode("a501022008215820394fd5a1e33b8a67d5fa9ddca42d261219dde202e65bbf07bf2f671e157ac41f225820199d7db667e74905c8371168b815c267db76243fbfd387fa5f2d8a691099a89a2358203e0fada8be75e5e47ab4c1c91c3f8f9185d1e18a2a16b3400a1eb33c9cdf8b96").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::Secp256k1(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A public EC (P-256) key with a `kid` of
    /// "meriadoc.brandybuck@buckland.example".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.1>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn public_p256_1() {
        let input = hex::decode("a5200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c01020258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::P256(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A secret EC (P-256) key with a kid of
    /// "meriadoc.brandybuck@buckland.example".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.2>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn secret_p256_1() {
        let input = hex::decode("a601020258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::P256(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A public EC (P-256) key with a kid of "11".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.1>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn public_p256_2() {
        let input = hex::decode("a52001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e010202423131").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::P256(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A secret EC (P-256) key with a kid of "11".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.2>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn secret_p256_2() {
        let input = hex::decode("a60102024231312001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e23582057c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::P256(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A public EC (P-256) key with a kid of "peregrin.took@tuckborough.example".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.1>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn public_p256_3() {
        let input = hex::decode("a5200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280225820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb0102025821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::P256(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A secret EC (P-256) key with a kid of
    /// "peregrin.took@tuckborough.example".
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.2>
    #[cfg(feature = "secp256r1")]
    #[test]
    fn secret_p256_3() {
        let input = hex::decode("a601022001025821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c6521582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280225820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb23582002d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::P256(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A public EC (P-384) key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 2,
    ///   -1: 2,
    ///   -2: h'fa1d31d39853d37fbfd145675635d52795f5feb3eacf11371ad8c6eb30c6f2493b0ec74d8c5b5a20ebf68ce3e0bd2c07',
    ///   -3: h'7c2b27b366e4fc73b79d28bac0b18ae2f2b0c4e7849656a71aac8987e60af5af57a9af3faf206afc798fa5fb06db15aa'
    /// }
    /// ```
    #[cfg(feature = "secp384r1")]
    #[test]
    fn public_p384_1() {
        let input = hex::decode("a401022002215830fa1d31d39853d37fbfd145675635d52795f5feb3eacf11371ad8c6eb30c6f2493b0ec74d8c5b5a20ebf68ce3e0bd2c072258307c2b27b366e4fc73b79d28bac0b18ae2f2b0c4e7849656a71aac8987e60af5af57a9af3faf206afc798fa5fb06db15aa").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_public().unwrap();
        assert!(matches!(key, PublicKey::P384(_)));
        assert_eq!(
            CoseKey::encode_public_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }

    /// A secret EC (P-384) key.
    ///
    /// ```cbor-diagnostic
    /// {
    ///   1: 2,
    ///   -1: 2,
    ///   -2: h'fa1d31d39853d37fbfd145675635d52795f5feb3eacf11371ad8c6eb30c6f2493b0ec74d8c5b5a20ebf68ce3e0bd2c07',
    ///   -3: h'7c2b27b366e4fc73b79d28bac0b18ae2f2b0c4e7849656a71aac8987e60af5af57a9af3faf206afc798fa5fb06db15aa',
    ///   -4: h'21d8eb2250cdaa19bfb01f03211be11a70ef4739650ed954166531808aa254c1d6d968b36d16184d350600253fa672c0'
    /// }
    /// ```
    #[cfg(feature = "secp384r1")]
    #[test]
    fn secret_p384_1() {
        let input = hex::decode("a501022002215830fa1d31d39853d37fbfd145675635d52795f5feb3eacf11371ad8c6eb30c6f2493b0ec74d8c5b5a20ebf68ce3e0bd2c072258307c2b27b366e4fc73b79d28bac0b18ae2f2b0c4e7849656a71aac8987e60af5af57a9af3faf206afc798fa5fb06db15aa23583021d8eb2250cdaa19bfb01f03211be11a70ef4739650ed954166531808aa254c1d6d968b36d16184d350600253fa672c0").unwrap();
        let cose_key = CoseKey::from_slice(&input).unwrap();
        let key = cose_key.decode_secret().unwrap();
        assert!(matches!(key, SecretKey::P384(_)));
        assert_eq!(
            CoseKey::encode_secret_with_id(&key, cose_key.key_id.clone()).unwrap(),
            cose_key
        )
    }
}
