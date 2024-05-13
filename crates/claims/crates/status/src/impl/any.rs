use std::str::FromStr;

use iref::Uri;
use serde::Deserialize;
use ssi_jws::CompactJWS;
use ssi_jwt::JWTClaims;

use crate::{
    bitstream_status_list::{
        BitstringStatusListCredential, BitstringStatusListEntry,
        BitstringStatusListEntrySetCredential,
    },
    StatusMapEntry, StatusMapEntrySet,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid JWS: {0}")]
    Jws(#[from] ssi_jws::DecodeError),

    #[error("unrecognized status list")]
    UnrecognizedStatusMap,

    #[error("unrecognized credential")]
    UnrecognizedEntrySet,
}

pub enum AnyStatusMap {
    BitstringStatusList(BitstringStatusListCredential),
}

impl AnyStatusMap {
    /// Tries to decode any status list from the given bytes.
    pub fn decode(bytes: &[u8], media_type: Option<MediaType>) -> Result<(Self, MediaType), Error> {
        if media_type.accepts_json() {
            if let Ok(json) = serde_json::from_slice(bytes) {
                return match json {
                    AnyJsonStatusMap::BitstringStatusList(cred) => {
                        Ok((Self::BitstringStatusList(cred), MediaType::VcLdJson))
                    }
                    AnyJsonStatusMap::JwtVc(jwt_vc) => {
                        let result = Self::from_jwt_vc_claims(jwt_vc)?;
                        Ok((result, MediaType::Json))
                    }
                };
            }
        }

        if media_type.accepts_jws() {
            if let Ok(jws) = CompactJWS::new(bytes) {
                let payload = jws.decode()?.payload;
                return match serde_json::from_slice(&payload) {
                    Ok(jwt_vc) => {
                        let result = Self::from_jwt_vc_claims(jwt_vc)?;
                        Ok((result, MediaType::Jwt))
                    }
                    Err(_) => Err(Error::UnrecognizedStatusMap),
                };
            }
        }

        Err(Error::UnrecognizedStatusMap)
    }

    fn from_jwt_vc_claims(claims: JWTClaims) -> Result<Self, Error> {
        match ssi_vc::decode_jwt_vc_claims(claims) {
            Ok(cred) => match cred {
                AnyStatusMapCredential::BitstringStatusList(cred) => {
                    Ok(AnyStatusMap::BitstringStatusList(cred))
                }
            },
            Err(_) => Err(Error::UnrecognizedStatusMap),
        }
    }

    /// Returns the URL of the status list credential.
    pub fn credential_url(&self) -> Option<&Uri> {
        match self {
            Self::BitstringStatusList(cred) => cred.id.as_deref(),
        }
    }
}

macro_rules! media_types {
    ($($id:ident: $name:literal),*) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum MediaType {
            $($id),*
        }

        impl MediaType {
            pub fn new(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$id),)*
                    _ => None
                }
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$id => $name),*
                }
            }
        }
    };
}

media_types! {
    Json: "application/json",
    LdJson: "application/ld+json",
    VcLdJson: "application/vc+ld+json",
    Jwt: "application/jwt",
    SdJwt: "application/sd-jwt",
    Cwt: "application/cwt"
}

impl MediaType {
    pub fn is_json(&self) -> bool {
        matches!(self, Self::Json | Self::LdJson | Self::VcLdJson)
    }

    pub fn is_jws(&self) -> bool {
        matches!(self, Self::Jwt | Self::SdJwt)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown media type `{0}`")]
pub struct UnknownStatusMapMediaType(pub String);

impl FromStr for MediaType {
    type Err = UnknownStatusMapMediaType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s).ok_or_else(|| UnknownStatusMapMediaType(s.to_owned()))
    }
}

trait OptionalMediaType {
    fn accepts_json(&self) -> bool;

    fn accepts_jws(&self) -> bool;
}

impl OptionalMediaType for Option<MediaType> {
    fn accepts_json(&self) -> bool {
        self.as_ref().map(MediaType::is_json).unwrap_or(true)
    }

    fn accepts_jws(&self) -> bool {
        self.as_ref().map(MediaType::is_jws).unwrap_or(true)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnyJsonStatusMap {
    BitstringStatusList(BitstringStatusListCredential),
    JwtVc(ssi_jwt::JWTClaims),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnyStatusMapCredential {
    BitstringStatusList(BitstringStatusListCredential),
}

pub enum AnyEntrySet {
    BitstringStatusList(BitstringStatusListEntrySetCredential),
}

impl AnyEntrySet {
    pub fn decode(bytes: &[u8], media_type: Option<MediaType>) -> Result<(Self, MediaType), Error> {
        if media_type.accepts_json() {
            if let Ok(json) = serde_json::from_slice(bytes) {
                return match json {
                    AnyJsonStatusMapEntrySet::BitstringStatusList(cred) => {
                        Ok((Self::BitstringStatusList(cred), MediaType::VcLdJson))
                    }
                    AnyJsonStatusMapEntrySet::JwtVc(jwt_vc) => {
                        let result = Self::from_jwt_vc_claims(jwt_vc)?;
                        Ok((result, MediaType::Json))
                    }
                };
            }
        }

        if media_type.accepts_jws() {
            if let Ok(jws) = CompactJWS::new(bytes) {
                let payload = jws.decode()?.payload;
                return match serde_json::from_slice(&payload) {
                    Ok(jwt_vc) => {
                        let result = Self::from_jwt_vc_claims(jwt_vc)?;
                        Ok((result, MediaType::Jwt))
                    }
                    Err(_) => Err(Error::UnrecognizedEntrySet),
                };
            }
        }

        Err(Error::UnrecognizedEntrySet)
    }

    fn from_jwt_vc_claims(claims: JWTClaims) -> Result<Self, Error> {
        match ssi_vc::decode_jwt_vc_claims(claims) {
            Ok(cred) => match cred {
                AnyStatusMapEntrySetCredential::BitstringStatusList(cred) => {
                    Ok(AnyEntrySet::BitstringStatusList(cred))
                }
            },
            Err(_) => Err(Error::UnrecognizedEntrySet),
        }
    }
}

impl StatusMapEntrySet for AnyEntrySet {
    type Entry<'a> = AnyStatusMapEntryRef<'a> where Self: 'a;

    fn get_entry(&self, purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        match self {
            Self::BitstringStatusList(s) => s
                .get_entry(purpose)
                .map(AnyStatusMapEntryRef::BitstringStatusList),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnyJsonStatusMapEntrySet {
    BitstringStatusList(BitstringStatusListEntrySetCredential),
    JwtVc(ssi_jwt::JWTClaims),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnyStatusMapEntrySetCredential {
    BitstringStatusList(BitstringStatusListEntrySetCredential),
}

pub enum AnyStatusMapEntryRef<'a> {
    BitstringStatusList(&'a BitstringStatusListEntry),
}

impl<'a> StatusMapEntry for AnyStatusMapEntryRef<'a> {
    type Key = usize;

    fn status_list_url(&self) -> &Uri {
        match self {
            Self::BitstringStatusList(e) => e.status_list_url(),
        }
    }

    fn key(&self) -> Self::Key {
        match self {
            Self::BitstringStatusList(e) => e.key(),
        }
    }
}
