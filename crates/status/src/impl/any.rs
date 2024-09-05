use iref::Uri;
use ssi_claims_core::{DateTimeProvider, Eip712TypesLoaderProvider, ResolverProvider};
use ssi_json_ld::JsonLdLoaderProvider;
use ssi_jwk::JWKResolver;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};

use crate::{
    bitstring_status_list::{
        self, BitstringStatusListCredential, BitstringStatusListEntry,
        BitstringStatusListEntrySetCredential,
    },
    token_status_list::{self, StatusListToken},
    EncodedStatusMap, FromBytes, FromBytesOptions, StatusMap, StatusMapEntry, StatusMapEntrySet,
    StatusSizeError,
};

pub enum AnyStatusMap {
    BitstringStatusList(BitstringStatusListCredential),
    TokenStatusList(StatusListToken),
}

impl AnyStatusMap {
    /// Returns the URL of the status list credential.
    pub fn credential_url(&self) -> Option<&Uri> {
        match self {
            Self::BitstringStatusList(cred) => cred.id.as_deref(),
            Self::TokenStatusList(_) => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("unexpected media type `{0}`")]
    UnexpectedMediaType(String),

    #[error(transparent)]
    BitstringStatusList(bitstring_status_list::FromBytesError),

    #[error(transparent)]
    TokenStatusList(token_status_list::FromBytesError),
}

impl<V> FromBytes<V> for AnyStatusMap
where
    V: ResolverProvider + DateTimeProvider + JsonLdLoaderProvider + Eip712TypesLoaderProvider,
    V::Resolver: JWKResolver + VerificationMethodResolver<Method = AnyMethod>,
{
    type Error = FromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "statuslist+jwt" | "statuslist+cwt" => {
                StatusListToken::from_bytes_with(bytes, media_type, verifier, options)
                    .await
                    .map(AnyStatusMap::TokenStatusList)
                    .map_err(FromBytesError::TokenStatusList)
            }
            "application/vc+ld+json+jwt"
            | "application/vc+ld+json+sd-jwt"
            | "application/vc+ld+json+cose"
            | "application/vc+ld+json" => {
                BitstringStatusListCredential::from_bytes_with(bytes, media_type, verifier, options)
                    .await
                    .map(AnyStatusMap::BitstringStatusList)
                    .map_err(FromBytesError::BitstringStatusList)
            }
            other => Err(FromBytesError::UnexpectedMediaType(other.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error(transparent)]
    BitstringStatusList(#[from] bitstring_status_list::DecodeError),

    #[error(transparent)]
    TokenStatusList(#[from] token_status_list::DecodeError),
}

impl EncodedStatusMap for AnyStatusMap {
    type DecodeError = DecodeError;
    type Decoded = AnyDecodedStatusMap;

    fn decode(self) -> Result<Self::Decoded, Self::DecodeError> {
        match self {
            Self::BitstringStatusList(m) => m
                .decode()
                .map(AnyDecodedStatusMap::BitstringStatusList)
                .map_err(Into::into),
            Self::TokenStatusList(m) => m
                .decode()
                .map(AnyDecodedStatusMap::TokenStatusList)
                .map_err(Into::into),
        }
    }
}

#[derive(Clone)]
pub enum AnyDecodedStatusMap {
    BitstringStatusList(bitstring_status_list::StatusList),
    TokenStatusList(token_status_list::StatusList),
}

impl AnyDecodedStatusMap {
    pub fn iter(
        &self,
        status_size: Option<u8>,
    ) -> Result<AnyDecodedStatusMapIter, StatusSizeError> {
        match self {
            Self::BitstringStatusList(m) => Ok(AnyDecodedStatusMapIter::BitstringStatusList(
                m.iter(status_size.ok_or(StatusSizeError::Missing)?.try_into()?),
            )),
            Self::TokenStatusList(m) => Ok(AnyDecodedStatusMapIter::TokenStatusList(m.iter())),
        }
    }
}

impl StatusMap for AnyDecodedStatusMap {
    type Key = usize;
    type StatusSize = u8;
    type Status = u8;

    fn time_to_live(&self) -> Option<std::time::Duration> {
        match self {
            Self::BitstringStatusList(m) => m.time_to_live(),
            Self::TokenStatusList(m) => m.time_to_live(),
        }
    }

    fn get_by_key(
        &self,
        status_size: Option<u8>,
        key: Self::Key,
    ) -> Result<Option<Self::Status>, StatusSizeError> {
        match self {
            Self::BitstringStatusList(m) => {
                m.get_by_key(status_size.map(TryInto::try_into).transpose()?, key)
            }
            Self::TokenStatusList(m) => {
                m.get_by_key(status_size.map(TryInto::try_into).transpose()?, key)
            }
        }
    }
}

pub enum AnyDecodedStatusMapIter<'a> {
    BitstringStatusList(bitstring_status_list::BitStringIter<'a>),
    TokenStatusList(token_status_list::BitStringIter<'a>),
}

impl<'a> Iterator for AnyDecodedStatusMapIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::BitstringStatusList(i) => i.next(),
            Self::TokenStatusList(i) => i.next(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EntrySetFromBytesError {
    #[error(transparent)]
    TokenStatusList(#[from] token_status_list::EntrySetFromBytesError),

    #[error(transparent)]
    BitstringStatusList(#[from] bitstring_status_list::FromBytesError),

    #[error("unexpected media type `{0}`")]
    UnexpectedMediaType(String),
}

pub enum AnyEntrySet {
    BitstringStatusList(BitstringStatusListEntrySetCredential),
    TokenStatusList(token_status_list::AnyStatusListEntrySet),
}

impl<V> FromBytes<V> for AnyEntrySet
where
    V: ResolverProvider + DateTimeProvider + JsonLdLoaderProvider + Eip712TypesLoaderProvider,
    V::Resolver: JWKResolver + VerificationMethodResolver<Method = AnyMethod>,
{
    type Error = EntrySetFromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        params: &V,
        options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "application/json" | "application/jwt" | "application/cbor" | "application/cwt" => {
                token_status_list::AnyStatusListEntrySet::from_bytes_with(
                    bytes, media_type, params, options,
                )
                .await
                .map(Self::TokenStatusList)
                .map_err(Into::into)
            }
            "application/vc+ld+json+jwt"
            | "application/vc+ld+json+sd-jwt"
            | "application/vc+ld+json+cose"
            | "application/vc+ld+json" => {
                bitstring_status_list::BitstringStatusListEntrySetCredential::from_bytes_with(
                    bytes, media_type, params, options,
                )
                .await
                .map(Self::BitstringStatusList)
                .map_err(Into::into)
            }
            other => Err(EntrySetFromBytesError::UnexpectedMediaType(
                other.to_owned(),
            )),
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
            Self::TokenStatusList(s) => s
                .get_entry(purpose)
                .map(AnyStatusMapEntryRef::TokenStatusList),
        }
    }
}

pub enum AnyStatusMapEntryRef<'a> {
    BitstringStatusList(&'a BitstringStatusListEntry),
    TokenStatusList(token_status_list::AnyStatusListReference<'a>),
}

impl<'a> StatusMapEntry for AnyStatusMapEntryRef<'a> {
    type Key = usize;
    type StatusSize = u8;

    fn status_list_url(&self) -> &Uri {
        match self {
            Self::BitstringStatusList(e) => e.status_list_url(),
            Self::TokenStatusList(e) => e.status_list_url(),
        }
    }

    fn key(&self) -> Self::Key {
        match self {
            Self::BitstringStatusList(e) => e.key(),
            Self::TokenStatusList(e) => e.key(),
        }
    }

    fn status_size(&self) -> Option<Self::StatusSize> {
        match self {
            Self::BitstringStatusList(e) => e.status_size().map(Into::into),
            Self::TokenStatusList(e) => e.status_size().map(Into::into),
        }
    }
}
