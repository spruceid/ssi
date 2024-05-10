use core::fmt;
use std::borrow::Cow;

use chrono::{DateTime, Utc};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum InvalidClaims {
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
/// Validation consists in verifying that the claims themselves are
/// consistent and valid with regard to the verification environment.
/// For instance, checking that a credential's expiration date is not in the
/// past, or the issue date not in the future.
///
/// Validation may fail even if the claims's proof is successfully verified.
pub trait Validate<E> {
    /// Validates the claims.
    fn validate(&self, env: &E) -> ClaimsValidity;
}

impl<E> Validate<E> for () {
    fn validate(&self, _env: &E) -> ClaimsValidity {
        Ok(())
    }
}

impl<E> Validate<E> for [u8] {
    fn validate(&self, _env: &E) -> ClaimsValidity {
        Ok(())
    }
}

impl<E> Validate<E> for Vec<u8> {
    fn validate(&self, _env: &E) -> ClaimsValidity {
        Ok(())
    }
}

impl<'a, E, T: ?Sized + ToOwned + Validate<E>> Validate<E> for Cow<'a, T> {
    fn validate(&self, _env: &E) -> ClaimsValidity {
        Ok(())
    }
}

/// Environment that provides date and time.
///
/// Used to check the validity period of given claims.
pub trait DateTimeEnvironment {
    /// Returns the current date and time.
    fn date_time(&self) -> DateTime<Utc>;
}

/// Validation environment.
///
/// This is a common environment implementation expected to work with most
/// claims.
///
/// It is possible to define a custom environment type, as long it implements
/// the accessor traits required for validation such as [`DateTimeEnvironment`].
pub struct ValidationEnvironment {
    pub date_time: DateTime<Utc>,
}

impl Default for ValidationEnvironment {
    fn default() -> Self {
        Self {
            date_time: Utc::now(),
        }
    }
}

impl DateTimeEnvironment for ValidationEnvironment {
    fn date_time(&self) -> DateTime<Utc> {
        self.date_time
    }
}
