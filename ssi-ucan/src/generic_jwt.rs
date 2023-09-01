use crate::{
    jwt::{decode_ucan_jwt, DummyHeader, Helper, Jwt, UcanDecode, UcanEncode},
    Error, Ucan,
};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, JWK};

#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
    alg: String,
    signature: Vec<u8>,
}

impl Signature {
    pub fn new(alg: String, signature: Vec<u8>) -> Self {
        Self { alg, signature }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.signature
    }

    pub fn alg(&self) -> &str {
        self.alg.as_str()
    }
}

impl<'a, 's, F, A> Helper<'a, 's, Jwt> for Ucan<Signature, F, A>
where
    DummyHeader<String>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Signed = &'a str;
    type Raw = &'a str;
    type Signature = &'s [u8];
    fn transform(
        &'s self,
        signed: Self::Raw,
        jwk: &JWK,
    ) -> Result<(Algorithm, Self::Signed, Self::Signature), Error> {
        Ok((
            jwk.algorithm.unwrap_or(Algorithm::ES256),
            signed,
            self.signature().bytes(),
        ))
    }
}

impl<'a, F, A> UcanDecode<'a, Jwt> for Ucan<Signature, F, A>
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
            signature: Signature::new(header.alg, sig),
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
