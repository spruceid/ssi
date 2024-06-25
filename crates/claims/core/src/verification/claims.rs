use chrono::{DateTime, Utc};
use core::fmt;
use std::borrow::Cow;

pub use ssi_eip712::Eip712TypesEnvironment;
pub use ssi_json_ld::ContextLoaderEnvironment;

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
/// Validation consists in verifying that the claims themselves are
/// consistent and valid with regard to the verification environment.
/// For instance, checking that a credential's expiration date is not in the
/// past, or the issue date not in the future.
///
/// Validation may fail even if the claims's proof is successfully verified.
///
/// The `validate` function is also provided with the proof, as some claim type
/// require information from the proof to be validated.
pub trait Validate<E, P> {
    /// Validates the claims.
    fn validate(&self, env: &E, proof: &P) -> ClaimsValidity;
}

impl<E, P> Validate<E, P> for () {
    fn validate(&self, _env: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<E, P> Validate<E, P> for [u8] {
    fn validate(&self, _env: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<E, P> Validate<E, P> for Vec<u8> {
    fn validate(&self, _env: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<'a, E, P, T: ?Sized + ToOwned + Validate<E, P>> Validate<E, P> for Cow<'a, T> {
    fn validate(&self, _env: &E, _proof: &P) -> ClaimsValidity {
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

impl DateTimeEnvironment for () {
    fn date_time(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Verifiable claims with a preferred default verification environment.
pub trait DefaultVerificationEnvironment {
    type Environment: Default;
}

impl DefaultVerificationEnvironment for () {
    type Environment = ();
}

impl DefaultVerificationEnvironment for [u8] {
    type Environment = ();
}

impl DefaultVerificationEnvironment for Vec<u8> {
    type Environment = ();
}

impl<'a> DefaultVerificationEnvironment for Cow<'a, [u8]> {
    type Environment = ();
}

impl<'a, T: DefaultVerificationEnvironment> DefaultVerificationEnvironment for &'a T {
    type Environment = T::Environment;
}

/// Verification environment.
///
/// This is a common environment implementation expected to work with most
/// claims.
///
/// It is possible to define a custom environment type, as long it implements
/// the accessor traits required for verification such as
/// [`DateTimeEnvironment`].
pub struct VerificationEnvironment<JsonLdLoader = ssi_json_ld::ContextLoader, Eip712Loader = ()> {
    pub date_time: DateTime<Utc>,

    pub json_ld_loader: JsonLdLoader,

    pub eip712_loader: Eip712Loader,
}

impl Default for VerificationEnvironment {
    fn default() -> Self {
        Self {
            date_time: Utc::now(),
            json_ld_loader: ssi_json_ld::ContextLoader::default(),
            eip712_loader: (),
        }
    }
}

impl DateTimeEnvironment for VerificationEnvironment {
    fn date_time(&self) -> DateTime<Utc> {
        self.date_time
    }
}

impl<JsonLdLoader, Eip712Loader> ContextLoaderEnvironment
    for VerificationEnvironment<JsonLdLoader, Eip712Loader>
where
    JsonLdLoader: ssi_json_ld::Loader,
{
    type Loader = JsonLdLoader;

    fn loader(&self) -> &Self::Loader {
        &self.json_ld_loader
    }
}

impl<JsonLdLoader, Eip712Loader> Eip712TypesEnvironment
    for VerificationEnvironment<JsonLdLoader, Eip712Loader>
where
    Eip712Loader: ssi_eip712::TypesProvider,
{
    type Provider = Eip712Loader;

    fn eip712_types(&self) -> &Self::Provider {
        &self.eip712_loader
    }
}
