use std::time::Duration;

mod r#impl;
use iref::Uri;
pub use r#impl::*;
pub mod client;

pub trait EncodedStatusMap {
    type Decoded: StatusMap;
    type DecodeError: std::error::Error;

    fn decode(self) -> Result<Self::Decoded, Self::DecodeError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FromBytesOptions {
    /// Allow unsecured claims.
    pub allow_unsecured: bool,
}

impl FromBytesOptions {
    pub const ALLOW_UNSECURED: Self = Self {
        allow_unsecured: true,
    };
}

pub trait FromBytes<V>: Sized {
    type Error: std::error::Error;

    #[allow(async_fn_in_trait)]
    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verification_params: &V,
        options: FromBytesOptions,
    ) -> Result<Self, Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn from_bytes(bytes: &[u8], media_type: &str, verifier: &V) -> Result<Self, Self::Error> {
        Self::from_bytes_with(bytes, media_type, verifier, FromBytesOptions::default()).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StatusSizeError {
    #[error("missing status size")]
    Missing,

    #[error("invalid status size")]
    Invalid,
}

pub trait StatusMap: Clone {
    type Key;
    type StatusSize;
    type Status;

    /// Maximum duration an implementer is allowed to cache a
    /// status list.
    fn time_to_live(&self) -> Option<Duration> {
        None
    }

    fn get_by_key(
        &self,
        status_size: Option<Self::StatusSize>,
        key: Self::Key,
    ) -> Result<Option<Self::Status>, StatusSizeError>;

    fn get_entry<E: StatusMapEntry<Key = Self::Key, StatusSize = Self::StatusSize>>(
        &self,
        entry: &E,
    ) -> Result<Option<Self::Status>, StatusSizeError> {
        self.get_by_key(entry.status_size(), entry.key())
    }
}

pub trait StatusMapEntrySet {
    type Entry<'a>: StatusMapEntry
    where
        Self: 'a;

    fn get_entry(&self, purpose: StatusPurpose<&str>) -> Option<Self::Entry<'_>>;
}

pub trait StatusMapEntry {
    type Key;
    type StatusSize;

    fn status_list_url(&self) -> &Uri;

    fn status_size(&self) -> Option<Self::StatusSize>;

    fn key(&self) -> Self::Key;
}

impl<'a, E: StatusMapEntry> StatusMapEntry for &'a E {
    type Key = E::Key;
    type StatusSize = E::StatusSize;

    fn status_list_url(&self) -> &Uri {
        E::status_list_url(*self)
    }

    fn status_size(&self) -> Option<Self::StatusSize> {
        E::status_size(*self)
    }

    fn key(&self) -> Self::Key {
        E::key(*self)
    }
}

pub enum StatusPurpose<T = String> {
    /// Cancel the validity of a verifiable credential.
    ///
    /// This status is not reversible.
    Revocation,

    /// Temporarily prevent the acceptance of a verifiable credential.
    ///
    /// This status is reversible.
    Suspension,

    /// Other purpose whose semantics is not supported by `ssi-status`.
    Other(T),
}
