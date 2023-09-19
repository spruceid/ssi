use crate::{Payload, Ucan, UcanDecode, UcanEncode};
use serde::{Deserialize, Serialize};
pub use ssi_jwk::{Algorithm, JWK};
use ssi_jws::split_jws;

pub struct Jwt;

pub trait JwtSignatureSer {
    type Alg<'a>
    where
        Self: 'a;
    type Signature<'s>
    where
        Self: 's;
    fn alg(&self) -> Self::Alg<'_>;
    fn sig(&self) -> Self::Signature<'_>;
}

pub trait JwtSignatureDe {
    type Alg;
    type Signature;
    type Error;
    fn from_header(a: Self::Alg, s: Self::Signature) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeError<S: std::error::Error> {
    #[error("Invalid DID URL")]
    DIDURL,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidJws(S),
    #[error("Invalid Header Type, expected 'JWT', found {0}")]
    InvalidHeaderType(String),
    #[error("Invalid Jwt String")]
    InvalidJwtString,
}

impl<S> From<EncodeError> for DecodeError<S>
where
    S: std::error::Error,
{
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::Base64(e) => DecodeError::Base64(e),
            EncodeError::Json(e) => DecodeError::Json(e),
        }
    }
}

impl<F, A, S> UcanDecode<Jwt> for Ucan<F, A, S>
where
    F: for<'d> Deserialize<'d>,
    A: for<'d> Deserialize<'d>,
    S: JwtSignatureDe,
    S::Alg: for<'d> Deserialize<'d>,
    S::Signature: From<Vec<u8>>,
    S::Error: std::error::Error,
{
    type Error = DecodeError<S::Error>;
    type Encoded<'e> = &'e str;
    fn decode(jwt: Self::Encoded<'_>) -> Result<Self, Self::Error> {
        let (alg, payload, sig) = decode_ucan_jwt::<F, A, S::Alg, S::Error>(jwt)?;
        Ok(Self {
            payload,
            signature: S::from_header(alg, sig.into()).map_err(DecodeError::InvalidJws)?,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EncodeError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl<F, A, S> UcanEncode<Jwt> for Ucan<F, A, S>
where
    F: Serialize,
    A: Serialize,
    S: JwtSignatureSer,
    for<'a> S::Alg<'a>: Serialize,
    for<'a> S::Signature<'a>: AsRef<[u8]>,
{
    type Error = EncodeError;
    type Encoded<'a> = String where Self: 'a;
    /// Encode the UCAN in canonicalized form, by encoding the JWS segments
    /// as JCS/DAG-JSON
    fn encode(&self) -> Result<String, Self::Error> {
        Ok([
            base64::encode_config(
                serde_jcs::to_string(&DummyHeader::new(self.signature.alg()))?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                serde_jcs::to_string(&self.payload)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature.sig().as_ref(), base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
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

    pub(crate) fn check_type(&self) -> Result<(), &str> {
        if self.typ != "JWT" {
            Err(&self.typ)
        } else {
            Ok(())
        }
    }
}

impl<A> DummyHeader<A> {
    pub fn from_str<E>(h: &str) -> Result<Self, DecodeError<E>>
    where
        Self: for<'a> Deserialize<'a>,
        E: std::error::Error,
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

fn decode_ucan_jwt<F, NB, A, E>(jwt: &str) -> Result<(A, Payload<F, NB>, Vec<u8>), DecodeError<E>>
where
    A: for<'d> Deserialize<'d>,
    F: for<'d> Deserialize<'d>,
    NB: for<'d> Deserialize<'d>,
    E: std::error::Error,
{
    let parts = split_jws(jwt).map_err(|_| DecodeError::InvalidJwtString)?;

    let header = DummyHeader::<A>::from_str(parts.0)?;

    // header can only contain 'typ' and 'alg' fields
    header
        .check_type()
        .map_err(|t| DecodeError::InvalidHeaderType(t.to_string()))?;

    let payload: Payload<F, NB> =
        serde_json::from_slice(&base64::decode_config(parts.1, base64::URL_SAFE_NO_PAD)?)?;

    // aud must be a DID
    if !payload.audience.starts_with("did:") {
        return Err(DecodeError::DIDURL);
    }

    // iss must be a DID
    if !payload.issuer.starts_with("did:") {
        return Err(DecodeError::DIDURL);
    }

    let sig = base64::decode_config(&parts.2, base64::URL_SAFE_NO_PAD)?;
    Ok((header.alg, payload, sig))
}
