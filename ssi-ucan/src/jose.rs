use crate::{
    jwt::{decode_ucan_jwt, DummyHeader, Jwt, Transformable, UcanDecode, UcanEncode},
    Error, Ucan,
};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, JWK};

#[derive(Clone, PartialEq, Debug)]
pub enum Signature {
    ES256([u8; 64]),
    ES512([u8; 128]),
    EdDSA([u8; 64]),
    RS256(Vec<u8>),
    RS512(Vec<u8>),
    ES256K([u8; 64]),
}

impl Signature {
    pub fn new_jws(alg: Algorithm, data: Vec<u8>) -> Result<Self, Error> {
        Ok(match alg {
            Algorithm::ES256 => Self::ES256(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Algorithm::EdDSA => Self::EdDSA(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Algorithm::RS256 => Self::RS256(data),
            Algorithm::RS512 => Self::RS512(data),
            Algorithm::ES256K => Self::ES256K(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::ES256(sig) => sig,
            Self::ES512(sig) => sig,
            Self::EdDSA(sig) => sig,
            Self::RS256(sig) => sig,
            Self::RS512(sig) => sig,
            Self::ES256K(sig) => sig,
        }
    }

    pub fn alg(&self) -> Algorithm {
        match self {
            Signature::ES256(_) => Algorithm::ES256,
            Signature::ES512(_) => Algorithm::ES256,
            Signature::EdDSA(_) => Algorithm::EdDSA,
            Signature::RS256(_) => Algorithm::RS256,
            Signature::RS512(_) => Algorithm::RS512,
            Signature::ES256K(_) => Algorithm::ES256K,
        }
    }
}

impl<'a, 's, F, A> Transformable<'a, 's, Jwt> for Ucan<Signature, F, A>
where
    DummyHeader<Algorithm>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Signed = &'a str;
    type Raw = &'a str;
    type Signature = &'s [u8];
    fn transform(
        &'s self,
        signed: Self::Raw,
        _: &JWK,
    ) -> Result<(Algorithm, Self::Signed, Self::Signature), Error> {
        Ok((self.signature().alg(), signed, self.signature().bytes()))
    }
}

impl<'a, F, A> UcanDecode<'a, Jwt> for Ucan<Signature, F, A>
where
    DummyHeader<Algorithm>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Error = Error;
    type Encoded = &'a str;
    fn decode(jwt: &'a str) -> Result<Self, Error> {
        let (header, payload, sig) = decode_ucan_jwt(jwt)?;
        Ok(Self {
            payload,
            signature: Signature::new_jws(header.alg, sig)?,
        })
    }
}

impl<F, A> UcanEncode<Jwt> for Ucan<Signature, F, A>
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
            base64::encode_config(&self.signature.bytes(), base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
}
