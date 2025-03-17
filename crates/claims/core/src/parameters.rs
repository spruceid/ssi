use chrono::{DateTime, Utc};

/// Common parameters for signature and verification.
///
/// The [`VerifiableClaims::verify`] function expects a set of verification
/// parameters necessary for the validation of claims and signature.
///
/// Required parameters depend on the actual type of claims and signature you
/// want to validate, however we can identify a subset of parameters that are
/// commonly required, namely:
///  - A public key resolver,
///  - a JSON-LD document loader,
///  - an EIP-712 types definition loader,
///  - the date and time.
///
/// This type provides this subset of parameters. In most cases, this will be
/// sufficient to verify all your secured claims.
///
/// [`VerifiableClaims::verify`]: super::VerifiableClaims::verify
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    /// Date-time.
    ///
    /// If `None`, the current date time is used.
    pub date_time: DateTime<Utc>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new(Utc::now())
    }
}

impl Parameters {
    pub fn new(date_time: DateTime<Utc>) -> Self {
        Self { date_time }
    }

    pub fn get<T: 'static + Send + Sync>(&self) -> Option<&T> {
        todo!()
    }
}
