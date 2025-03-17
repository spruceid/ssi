use ssi_crypto::{key::{KeyConversionError, KeyGenerationFailed}, rand};

use crate::{Base64urlUInt, OkpParams, Params, JWK};

use super::ED25519;

impl OkpParams {
    pub fn generate_ed25519() -> Result<Self, KeyGenerationFailed> {
        #[cfg(feature = "ring")]
        {
            let rng = ring::rand::SystemRandom::new();
            let mut key_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| KeyGenerationFailed)?
                .as_ref()
                .to_vec();
            // reference: ring/src/ec/curve25519/ed25519/signing.rs
            let private_key = key_pkcs8[0x10..0x30].to_vec();
            let public_key = key_pkcs8[0x35..0x55].to_vec();
            key_pkcs8.zeroize();
            Ok(Self {
                curve: ED25519.to_string(),
                public_key: Base64urlUInt(public_key),
                private_key: Some(Base64urlUInt(private_key)),
            })
        }
        #[cfg(not(feature = "ring"))]
        {
            let mut csprng = rand::rngs::OsRng {};
            let secret = ssi_crypto::ed25519::SigningKey::generate(&mut csprng);
            let public = secret.verifying_key();
            Ok(Self {
                curve: ED25519.to_string(),
                public_key: Base64urlUInt(public.as_ref().to_vec()),
                private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
            })
        }
    }

    pub fn generate_ed25519_from(
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<JWK, KeyGenerationFailed> {
        let secret = ssi_crypto::ed25519::SigningKey::generate(rng);
        let public = secret.verifying_key();
        Ok(JWK::from(Params::Okp(OkpParams {
            curve: ED25519.to_string(),
            public_key: Base64urlUInt(public.as_ref().to_vec()),
            private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
        })))
    }

    pub fn from_public_ed25519_bytes(data: &[u8]) -> Result<JWK, KeyConversionError> {
        let public_key = ssi_crypto::ed25519::VerifyingKey::try_from(data)
            .map_err(|_| KeyConversionError::Invalid)?;
        Ok(public_key.into())
    }

    pub fn from_secret_ed25519_bytes(data: &[u8]) -> Result<JWK, KeyConversionError> {
        let key: ssi_crypto::ed25519::SigningKey =
            data.try_into().map_err(|_| KeyConversionError::Invalid)?;
        Ok(JWK::from(Params::Okp(OkpParams {
            curve: ED25519.to_string(),
            public_key: Base64urlUInt(
                ssi_crypto::ed25519::VerifyingKey::from(&key)
                    .as_bytes()
                    .to_vec(),
            ),
            private_key: Some(Base64urlUInt(data.to_owned())),
        })))
    }

    pub fn to_public_ed25519(
        &self,
    ) -> Result<ssi_crypto::ed25519::VerifyingKey, KeyConversionError> {
        if self.curve != *ED25519 {
            return Err(KeyConversionError::Unsupported);
        }

        self.public_key
            .0
            .as_slice()
            .as_ref()
            .try_into()
            .map_err(|_| KeyConversionError::Invalid)
    }

    pub fn to_secret_ed25519(&self) -> Result<ssi_crypto::ed25519::SigningKey, KeyConversionError> {
        if self.curve != *ED25519 {
            return Err(KeyConversionError::Unsupported);
        }

        let private_key = self
            .private_key
            .as_ref()
            .ok_or(KeyConversionError::NotSecret)?;

        private_key
            .0
            .as_slice()
            .as_ref()
            .try_into()
            .map_err(|_| KeyConversionError::Invalid)
    }
}

#[cfg(feature = "ring")]
impl TryFrom<&OkpParams> for &ring::signature::EdDSAParameters {
    type Error = Error;

    fn try_from(params: &OkpParams) -> Result<Self, Self::Error> {
        if params.curve != *ED25519 {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(&ring::signature::ED25519)
    }
}

#[cfg(feature = "ring")]
impl TryFrom<&OkpParams> for ring::signature::Ed25519KeyPair {
    type Error = Error;
    fn try_from(params: &OkpParams) -> Result<Self, Self::Error> {
        if params.curve != *ED25519 {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        params
            .private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let der = simple_asn1::der_encode(params)?;
        let keypair = Self::from_pkcs8_maybe_unchecked(&der)?;
        Ok(keypair)
    }
}

impl JWK {
    pub fn generate_ed25519() -> Result<JWK, KeyGenerationFailed> {
        OkpParams::generate_ed25519().map(Into::into)
    }

    pub fn generate_ed25519_from(
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<JWK, KeyGenerationFailed> {
        OkpParams::generate_ed25519_from(rng).map(Into::into)
    }

    pub fn from_public_ed25519_bytes(data: &[u8]) -> Result<JWK, KeyConversionError> {
        OkpParams::from_public_ed25519_bytes(data).map(Into::into)
    }

    pub fn from_secret_ed25519_bytes(data: &[u8]) -> Result<JWK, KeyConversionError> {
        OkpParams::from_secret_ed25519_bytes(data).map(Into::into)
    }
}

impl TryFrom<&OkpParams> for ssi_crypto::ed25519::VerifyingKey {
    type Error = KeyConversionError;

    fn try_from(params: &OkpParams) -> Result<Self, Self::Error> {
        params.to_public_ed25519()
    }
}

impl TryFrom<&OkpParams> for ssi_crypto::ed25519::SigningKey {
    type Error = KeyConversionError;

    fn try_from(params: &OkpParams) -> Result<Self, Self::Error> {
        params.to_secret_ed25519()
    }
}

impl From<ssi_crypto::ed25519::VerifyingKey> for JWK {
    fn from(value: ssi_crypto::ed25519::VerifyingKey) -> Self {
        JWK::from(Params::Okp(OkpParams {
            curve: ED25519.to_string(),
            public_key: Base64urlUInt(value.to_bytes().to_vec()),
            private_key: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::JWK;

    const ED25519_JSON: &str = include_str!("../../../../../../tests/ed25519-2020-10-18.json");

    #[test]
    fn ed25519_from_str() {
        let _jwk: JWK = serde_json::from_str(ED25519_JSON).unwrap();
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn generate_ed25519() {
        let _key = JWK::generate_ed25519().unwrap();
    }
}
