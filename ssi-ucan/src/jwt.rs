use crate::{Error, Payload, Ucan};
use serde::{Deserialize, Serialize};
use ssi_dids::did_resolve::DIDResolver;
pub use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{split_jws, verify_bytes};

impl<'a, S, F, A> Ucan<S, F, A>
where
    Self: UcanDecode<'a, Jwt, Encoded = &'a str, Error = Error>
        + for<'s> Helper<'a, 's, Jwt, Raw = &'a str>,
    for<'s> <Self as Helper<'a, 's, Jwt>>::Signed: AsRef<[u8]>,
    for<'s> <Self as Helper<'a, 's, Jwt>>::Signature: AsRef<[u8]>,
{
    /// Decode the UCAN and verify it's signature
    ///
    /// This method will resolve the DID of the issuer and verify the signature
    /// using their public key. This method works over a JWT as the original
    /// encoding is not retained by the UCAN struct.
    pub async fn decode_and_verify(
        jwt: &'a str,
        resolver: &dyn DIDResolver,
    ) -> Result<Self, Error> {
        let ucan = Self::decode(jwt)?;
        let jwk = ucan.get_verification_key(resolver).await?;

        let signed = jwt.rsplit_once('.').ok_or(ssi_jws::Error::InvalidJWS)?.0;

        ucan.transform(signed, &jwk)
            .and_then(|(a, s, sig)| Ok(verify_bytes(a, s.as_ref(), &jwk, sig.as_ref())?))
            .map(|()| ucan)
    }
}

pub trait Helper<'a, 's, E>: UcanDecode<'a, E> {
    type Signed;
    type Raw: 'a;
    type Signature: 's;
    fn transform(
        &'s self,
        signed: Self::Raw,
        jwk: &JWK,
    ) -> Result<(Algorithm, Self::Signed, Self::Signature), Error>;
}

pub trait UcanDecode<'a, E> {
    type Error;
    type Encoded: 'a;
    /// Decode the UCAN from a jwt string
    fn decode(encoded: Self::Encoded) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub struct Jwt;

pub trait UcanEncode<E> {
    type Error;
    type Encoded;
    /// Encode the UCAN in canonicalized form, by encoding the JWS segments
    /// as JCS/DAG-JSON
    fn encode(&self) -> Result<Self::Encoded, Self::Error>;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DummyHeader<A = Algorithm> {
    pub alg: A,
    typ: String,
}

impl<A> DummyHeader<A> {
    pub fn new(alg: A) -> Self {
        Self {
            alg,
            typ: "JWT".to_string(),
        }
    }

    pub fn check_type(&self) -> Result<(), Error> {
        if self.typ != "JWT" {
            Err(Error::InvalidHeaderEntries)
        } else {
            Ok(())
        }
    }
}

impl<A> DummyHeader<A> {
    pub fn from_str(h: &str) -> Result<Self, Error>
    where
        Self: for<'a> Deserialize<'a>,
    {
        Ok(serde_json::from_slice(&base64::decode_config(
            h,
            base64::URL_SAFE_NO_PAD,
        )?)?)
    }
}

impl<A> From<A> for DummyHeader<A> {
    fn from(alg: A) -> Self {
        Self::new(alg)
    }
}

pub(crate) fn decode_ucan_jwt<F, NB, A>(
    jwt: &str,
) -> Result<(DummyHeader<A>, Payload<F, NB>, Vec<u8>), Error>
where
    DummyHeader<A>: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    NB: for<'d> Deserialize<'d>,
{
    let parts = split_jws(jwt)?;

    let header = DummyHeader::<A>::from_str(parts.0)?;

    // header can only contain 'typ' and 'alg' fields
    header.check_type()?;

    let payload: Payload<F, NB> =
        serde_json::from_slice(&base64::decode_config(parts.1, base64::URL_SAFE_NO_PAD)?)?;

    // aud must be a DID
    if !payload.audience.starts_with("did:") {
        return Err(Error::DIDURL);
    }

    // iss must be a DID
    if !payload.issuer.starts_with("did:") {
        return Err(Error::DIDURL);
    }

    let sig = base64::decode_config(&parts.2, base64::URL_SAFE_NO_PAD)?;
    Ok((header, payload, sig))
}
