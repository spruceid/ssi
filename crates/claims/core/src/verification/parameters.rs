use crate::{DateTimeProvider, ResolverProvider};
use chrono::{DateTime, Utc};
use ssi_eip712::Eip712TypesLoaderProvider;
use ssi_json_ld::JsonLdLoaderProvider;

/// Common verification parameters.
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
#[derive(Debug, Default, Clone, Copy)]
pub struct VerificationParameters<R, L1 = ssi_json_ld::ContextLoader, L2 = ()> {
    /// Public key resolver.
    pub resolver: R,

    /// JSON-LD loader.
    pub json_ld_loader: L1,

    /// EIP-712 types loader.
    pub eip712_types_loader: L2,

    /// Date-time.
    ///
    /// If `None`, the current date time is used.
    pub date_time: Option<DateTime<Utc>>,
}

impl<R> VerificationParameters<R> {
    pub fn from_resolver(resolver: R) -> Self {
        Self {
            resolver,
            json_ld_loader: ssi_json_ld::ContextLoader::default(),
            eip712_types_loader: (),
            date_time: None,
        }
    }
}

impl<R, L1, L2> VerificationParameters<R, L1, L2> {
    pub fn with_date_time(mut self, date_time: DateTime<Utc>) -> Self {
        self.date_time = Some(date_time);
        self
    }

    pub fn with_json_ld_loader<L>(self, loader: L) -> VerificationParameters<R, L, L2> {
        VerificationParameters {
            resolver: self.resolver,
            json_ld_loader: loader,
            eip712_types_loader: self.eip712_types_loader,
            date_time: self.date_time,
        }
    }

    pub fn with_eip712_types_loader<L>(self, loader: L) -> VerificationParameters<R, L1, L> {
        VerificationParameters {
            resolver: self.resolver,
            json_ld_loader: self.json_ld_loader,
            eip712_types_loader: loader,
            date_time: self.date_time,
        }
    }
}

impl<R, L1, L2> ResolverProvider for VerificationParameters<R, L1, L2> {
    type Resolver = R;

    fn resolver(&self) -> &Self::Resolver {
        &self.resolver
    }
}

impl<R, L1: ssi_json_ld::Loader, L2> JsonLdLoaderProvider for VerificationParameters<R, L1, L2> {
    type Loader = L1;

    fn loader(&self) -> &Self::Loader {
        &self.json_ld_loader
    }
}

impl<R, L1, L2: ssi_eip712::TypesLoader> Eip712TypesLoaderProvider
    for VerificationParameters<R, L1, L2>
{
    type Loader = L2;

    fn eip712_types(&self) -> &Self::Loader {
        &self.eip712_types_loader
    }
}

impl<R, L1, L2> DateTimeProvider for VerificationParameters<R, L1, L2> {
    fn date_time(&self) -> DateTime<Utc> {
        self.date_time.unwrap_or_else(Utc::now)
    }
}
