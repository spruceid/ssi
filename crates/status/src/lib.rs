use std::time::Duration;

mod r#impl;
use iref::Uri;
pub use r#impl::*;
pub mod client;

/// Encoded [`StatusMap`].
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

/// Status map.
///
/// A status map is a map from [`StatusMapEntry`] to [`StatusMap::Status`].
/// The [`StatusMapEntry`] is generally found in the credential or claims you
/// need to verify.
pub trait StatusMap: Clone {
    /// Key indexing each status in the map.
    type Key;

    /// Status bit size type.
    type StatusSize;

    /// Status type.
    type Status;

    /// Maximum duration an implementer is allowed to cache a
    /// status list.
    fn time_to_live(&self) -> Option<Duration> {
        None
    }

    /// Returns a status using the given status size and key.
    ///
    /// If `status_size` is `None`, it is assumed that the map itself knows the
    /// status size. If it does not, a [`StatusSizeError::Missing`] error is
    /// returned.
    fn get_by_key(
        &self,
        status_size: Option<Self::StatusSize>,
        key: Self::Key,
    ) -> Result<Option<Self::Status>, StatusSizeError>;

    /// Returns the status associated to the given entry.
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

/// Status map entry.
///
/// A status map entry is a reference to a particular status in a status map.
/// It links to a status map, providing a key in this map.
pub trait StatusMapEntry {
    /// Key indexing each status in the referenced status list.
    type Key;

    /// Status map status size type.
    type StatusSize;

    /// URL to the status map.
    fn status_list_url(&self) -> &Uri;

    /// Size of each status in the status map, if it is known by the entry.
    ///
    /// For some [`StatusMap`] implementations such as
    /// [`crate::token_status_list::StatusList`] the status size is stored in
    /// the map, while for some other implementations such as
    /// [`crate::bitstring_status_list::StatusList`] the status size is stored
    /// in the entry
    /// ([`crate::bitstring_status_list::BitstringStatusListEntry`]).
    ///
    /// If this function returns `None`, it is assumed that the status size
    /// will be provided by the status map.
    fn status_size(&self) -> Option<Self::StatusSize>;

    /// Entry key.
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
