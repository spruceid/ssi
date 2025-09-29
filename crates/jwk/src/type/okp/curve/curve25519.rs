use crate::{Base64urlUInt, Error, OctetParams, Params, JWK};

impl JWK {
    pub fn generate_ed25519() -> Result<JWK, Error> {
        #[cfg(feature = "ring")]
        {
            use zeroize::Zeroize;
            let rng = ring::rand::SystemRandom::new();
            let mut key_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?
                .as_ref()
                .to_vec();
            // reference: ring/src/ec/curve25519/ed25519/signing.rs
            let private_key = key_pkcs8[0x10..0x30].to_vec();
            let public_key = key_pkcs8[0x35..0x55].to_vec();
            key_pkcs8.zeroize();
            Ok(JWK::from(Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(public_key),
                private_key: Some(Base64urlUInt(private_key)),
            })))
        }
        #[cfg(not(feature = "ring"))]
        {
            let mut csprng = rand::rngs::OsRng {};
            let secret = ed25519_dalek::SigningKey::generate(&mut csprng);
            let public = secret.verifying_key();
            Ok(JWK::from(Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(public.as_ref().to_vec()),
                private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
            })))
        }
    }

    pub fn generate_ed25519_from(
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<JWK, Error> {
        let secret = ed25519_dalek::SigningKey::generate(rng);
        let public = secret.verifying_key();
        Ok(JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public.as_ref().to_vec()),
            private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
        })))
    }
}

impl TryFrom<&OctetParams> for ed25519_dalek::VerifyingKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(params.public_key.0.as_slice().as_ref().try_into()?)
    }
}

impl TryFrom<&OctetParams> for ed25519_dalek::SigningKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        let private_key = params
            .private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        Ok(private_key.0.as_slice().as_ref().try_into()?)
    }
}

#[cfg(feature = "ring")]
impl TryFrom<&OctetParams> for ring::signature::Ed25519KeyPair {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
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

pub fn ed25519_parse(data: &[u8]) -> Result<JWK, Error> {
    let public_key = ed25519_dalek::VerifyingKey::try_from(data)?;
    Ok(public_key.into())
}

impl From<ed25519_dalek::VerifyingKey> for JWK {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(value.to_bytes().to_vec()),
            private_key: None,
        }))
    }
}

pub fn ed25519_parse_private(data: &[u8]) -> Result<JWK, Error> {
    let key: ed25519_dalek::SigningKey = data.try_into()?;
    Ok(JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(ed25519_dalek::VerifyingKey::from(&key).as_bytes().to_vec()),
        private_key: Some(Base64urlUInt(data.to_owned())),
    })))
}

#[cfg(test)]
mod tests {
    use crate::JWK;

    const ED25519_JSON: &str = include_str!("../../../../../../tests/ed25519-2020-10-18.json");

    #[test]
    fn generate_ed25519() {
        let _key = JWK::generate_ed25519().unwrap();
    }

    #[test]
    fn ed25519_from_str() {
        let _jwk: JWK = serde_json::from_str(ED25519_JSON).unwrap();
    }
}
