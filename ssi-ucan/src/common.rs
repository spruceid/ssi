use super::{generic_jwt::Signature as GenericSig, jose::Signature, webauthn::Webauthn};
use crate::{
    jwt::{decode_ucan_jwt, DummyHeader, Jwt, Transformable, UcanDecode, UcanEncode},
    Error, Ucan,
};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, JWK};
use varsig::VarSigTrait;

#[derive(Clone, PartialEq, Debug)]
pub enum Common {
    Jose(Signature),
    Webauthn(Webauthn),
    Generic(GenericSig),
}

impl Common {
    pub fn new(alg: String, signature: Vec<u8>) -> Result<Self, Error> {
        Ok(match alg.as_str() {
            "ES256" => Self::Jose(Signature::new_jws(Algorithm::ES256, signature)?),
            "ES384" => Self::Jose(Signature::new_jws(Algorithm::ES384, signature)?),
            "RS256" => Self::Jose(Signature::new_jws(Algorithm::RS256, signature)?),
            "RS512" => Self::Jose(Signature::new_jws(Algorithm::RS512, signature)?),
            "EdDSA" => Self::Jose(Signature::new_jws(Algorithm::EdDSA, signature)?),
            "ES256K" => Self::Jose(Signature::new_jws(Algorithm::ES256K, signature)?),
            "Webauthn" => Self::Webauthn(Webauthn::from_bytes(&signature)?),
            _ => Self::Generic(GenericSig::new(alg, signature)),
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Self::Jose(sig) => sig.bytes().into(),
            Self::Webauthn(sig) => sig.to_vec()?,
            Self::Generic(sig) => sig.bytes().into(),
        })
    }

    pub fn alg(&self) -> &str {
        match self {
            Self::Jose(s) => match s.alg() {
                Algorithm::ES256 => "ES256",
                Algorithm::ES384 => "ES384",
                Algorithm::RS256 => "RS256",
                Algorithm::RS512 => "RS512",
                Algorithm::EdDSA => "EdDSA",
                Algorithm::ES256K => "ES256K",
                _ => "Unknown",
            },
            Self::Webauthn(_) => "Webauthn",
            Self::Generic(s) => s.alg(),
        }
    }
}

impl<'a, 's, F, A> Transformable<'a, 's, Jwt> for Ucan<Common, F, A>
where
    DummyHeader<String>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Signed = Vec<u8>;
    type Raw = &'a str;
    type Signature = Vec<u8>;
    fn transform(
        &'s self,
        _: Self::Raw,
        jwk: &JWK,
    ) -> Result<(Algorithm, Self::Signed, Self::Signature), Error> {
        use ssi_crypto::hashes::sha256::sha256;
        Ok((
            match &self.signature {
                Common::Jose(sig) => sig.alg(),
                Common::Webauthn(_) => jwk.algorithm.unwrap_or(Algorithm::ES256),
                Common::Generic(_) => jwk.algorithm.unwrap_or(Algorithm::ES256),
            },
            match &self.signature {
                Common::Jose(sig) => sig.bytes().into(),
                Common::Webauthn(sig) => {
                    [sig.authenticator_data(), &sha256(sig.client_data())].concat()
                }
                Common::Generic(sig) => sig.bytes().into(),
            },
            self.signature().to_vec()?,
        ))
    }
}

impl<'a, F, A> UcanDecode<'a, Jwt> for Ucan<Common, F, A>
where
    DummyHeader<String>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Error = Error;
    type Encoded = &'a str;
    fn decode(jwt: &'a str) -> Result<Self, Error> {
        let (header, payload, sig) = decode_ucan_jwt(jwt)?;
        Ok(Self {
            payload,
            signature: Common::new(header.alg, sig)?,
        })
    }
}

impl<F, A> UcanEncode<Jwt> for Ucan<Common, F, A>
where
    F: Serialize,
    A: Serialize,
{
    type Error = Error;
    type Encoded = String;
    fn encode(&self) -> Result<String, Error> {
        Ok([
            base64::encode_config(
                DagJsonCodec.encode(
                    &to_ipld(&DummyHeader::new(self.signature.alg())).map_err(IpldError::new)?,
                )?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.payload).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature.to_vec()?, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
}

impl From<Signature> for Common {
    fn from(sig: Signature) -> Self {
        Self::Jose(sig)
    }
}

impl From<Webauthn> for Common {
    fn from(sig: Webauthn) -> Self {
        Self::Webauthn(sig)
    }
}

impl From<GenericSig> for Common {
    fn from(sig: GenericSig) -> Self {
        Self::Generic(sig)
    }
}
