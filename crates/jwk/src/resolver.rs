use std::borrow::Cow;

use crate::JWK;
use ssi_claims_core::{
    chrono::{DateTime, Utc},
    DateTimeEnvironment, ProofValidationError, ResolverEnvironment,
};

/// JWK resolver.
///
/// Any type that can fetch a JWK from its identifier.
pub trait JWKResolver {
    /// Fetches a JWK by id.
    ///
    /// The key identifier is optional since the key may be known in advance.
    #[allow(async_fn_in_trait)]
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError>;
}

impl<'a, T: JWKResolver> JWKResolver for &'a T {
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError> {
        T::fetch_public_jwk(*self, key_id).await
    }
}

impl JWKResolver for JWK {
    async fn fetch_public_jwk(
        &self,
        _key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError> {
        Ok(Cow::Borrowed(self))
    }
}

impl ResolverEnvironment for JWK {
    type Resolver = Self;

    fn resolver(&self) -> &Self::Resolver {
        self
    }
}

impl DateTimeEnvironment for JWK {
    fn date_time(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
