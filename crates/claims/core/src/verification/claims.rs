use chrono::{DateTime, Utc};
use core::fmt;
use std::borrow::Cow;

pub use ssi_eip712::Eip712TypesLoaderProvider;
pub use ssi_json_ld::JsonLdLoaderProvider;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum InvalidClaims {
    #[error("missing issuance date")]
    MissingIssuanceDate,

    /// Validity period starts in the future.
    #[error("premature claim")]
    Premature {
        now: DateTime<Utc>,
        valid_from: DateTime<Utc>,
    },

    /// Validity period ends in the past.
    #[error("expired claim")]
    Expired {
        now: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },

    /// Uncommon validation error.
    #[error("{0}")]
    Other(String),
}

impl InvalidClaims {
    pub fn other(e: impl fmt::Display) -> Self {
        Self::Other(e.to_string())
    }
}

pub type ClaimsValidity = Result<(), InvalidClaims>;

/// Claims that can be validated.
///
/// This consists in verifying that the claims themselves are
/// consistent and valid with regard to the verification environment.
/// For instance, checking that a credential's expiration date is not in the
/// past, or the issue date not in the future.
///
/// Validation may fail even if the claims's proof is successfully verified.
///
/// The `validate` function is also provided with the proof, as some claim type
/// require information from the proof to be validated.
pub trait ValidateClaims<E, P = ()> {
    fn validate_claims(&self, _environment: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<E, P> ValidateClaims<E, P> for () {}

impl<E, P> ValidateClaims<E, P> for [u8] {}

impl<E, P> ValidateClaims<E, P> for Vec<u8> {}

impl<'a, E, P, T: ?Sized + ToOwned + ValidateClaims<E, P>> ValidateClaims<E, P> for Cow<'a, T> {}
