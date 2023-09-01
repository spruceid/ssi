use crate::{
    jwt::{decode_ucan_jwt, DummyHeader, Helper, Jwt, UcanDecode, UcanEncode},
    Error, Ucan,
};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, JWK};
pub use varsig::{common::webauthn::AssertionSigData as Webauthn, VarSigTrait};

impl<'a, 's, F, A> Helper<'a, 's, Jwt> for Ucan<Webauthn, F, A>
where
    DummyHeader<String>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Signed = Vec<u8>;
    type Raw = &'a str;
    type Signature = &'s [u8];
    fn transform(
        &'s self,
        signed: Self::Raw,
        jwk: &JWK,
    ) -> Result<(Algorithm, Self::Signed, Self::Signature), Error> {
        use ssi_crypto::hashes::sha256::sha256;

        let ccd = self.signature().parse_client_data()?;
        if ccd.challenge
            != base64::encode_config(sha256(signed.as_bytes()), base64::URL_SAFE_NO_PAD)
        {
            return Err(Error::ChallengeMismatch);
        };
        Ok((
            jwk.algorithm.unwrap_or(Algorithm::ES256),
            [
                self.signature().authenticator_data(),
                &sha256(self.signature().client_data()),
            ]
            .concat(),
            self.signature().signature(),
        ))
    }
}

impl<'a, F, A> UcanDecode<'a, Jwt> for Ucan<Webauthn, F, A>
where
    DummyHeader<String>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
{
    type Error = Error;
    type Encoded = &'a str;

    fn decode(jwt: &'a str) -> Result<Self, Error> {
        let (header, payload, sig) = decode_ucan_jwt::<F, A, String>(jwt)?;

        if header.alg != "webauthn" {
            return Err(Error::InvalidHeaderEntries);
        }

        Ok(Self {
            payload,
            signature: Webauthn::from_reader(&mut sig.as_slice())?,
        })
    }
}

impl<F, A> UcanEncode<Jwt> for Ucan<Webauthn, F, A>
where
    F: Serialize,
    A: Serialize,
{
    type Error = Error;
    type Encoded = String;
    fn encode_canonicalized_jwt(&self) -> Result<String, Error> {
        Ok([
            base64::encode_config(
                DagJsonCodec
                    .encode(&to_ipld(&DummyHeader::new("webauthn")).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.payload).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature().to_vec()?, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
}
