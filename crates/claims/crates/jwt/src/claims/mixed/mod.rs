use serde::Serialize;
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};
use ssi_jws::{JwsPayload, ValidateJwsHeader};
use std::borrow::Cow;

use super::{Claim, InfallibleClaimSet, RegisteredClaims};
use crate::{
    AnyClaims, ClaimSet, ExpirationTime, InvalidClaimValue, IssuedAt, Issuer, RegisteredClaim,
    Subject, TryIntoClaim,
};

mod de;

/// JSON Web Token claims.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct JWTClaims<T = AnyClaims> {
    /// Registered claims.
    #[serde(flatten)]
    pub registered: RegisteredClaims,

    /// Private claims.
    #[serde(flatten)]
    pub private: T,
}

impl JWTClaims {
    pub fn builder() -> JWTClaimsBuilder {
        JWTClaimsBuilder::default()
    }
}

impl<T> JWTClaims<T> {
    pub fn new() -> Self
    where
        T: Default,
    {
        Self::default()
    }

    pub fn from_private_claims(private: T) -> Self {
        Self {
            registered: RegisteredClaims::default(),
            private,
        }
    }
}

impl<T: ClaimSet> ClaimSet for JWTClaims<T> {
    fn contains<C: Claim>(&self) -> bool {
        ClaimSet::contains::<C>(&self.registered) || self.private.contains::<C>()
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
        match InfallibleClaimSet::get(&self.registered) {
            Some(claim) => Ok(Some(claim)),
            None => self.private.try_get(),
        }
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
        match InfallibleClaimSet::set(&mut self.registered, claim) {
            Ok(()) => Ok(Ok(())),
            Err(claim) => self.private.try_set(claim),
        }
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
        match InfallibleClaimSet::remove(&mut self.registered) {
            Some(claim) => Ok(Some(claim)),
            None => self.private.try_remove(),
        }
    }
}

impl<T: Serialize> JwsPayload for JWTClaims<T> {
    fn typ(&self) -> Option<&'static str> {
        Some("JWT")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<T, E> ValidateJwsHeader<E> for JWTClaims<T> {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        Ok(())
    }
}

impl<P, T: ClaimSet + ValidateClaims<E, P>, E> ValidateClaims<E, P> for JWTClaims<T>
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, proof: &P) -> ClaimsValidity {
        self.registered.validate_claims(env, proof)?;
        self.private.validate_claims(env, proof)
    }
}

#[derive(Default)]
pub struct JWTClaimsBuilder {
    registered: RegisteredClaims,
    error: bool,
}

impl JWTClaimsBuilder {
    pub fn set<C: RegisteredClaim>(mut self, value: impl TryIntoClaim<C>) -> Self {
        match value.try_into_claim() {
            Ok(value) => {
                self.registered.set(value);
            }
            Err(_) => self.error = true,
        }

        self
    }

    pub fn iss(self, value: impl TryIntoClaim<Issuer>) -> Self {
        self.set(value)
    }

    pub fn iat(self, value: impl TryIntoClaim<IssuedAt>) -> Self {
        self.set(value)
    }

    pub fn exp(self, value: impl TryIntoClaim<ExpirationTime>) -> Self {
        self.set(value)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, value: impl TryIntoClaim<Subject>) -> Self {
        self.set(value)
    }

    pub fn with_private_claims<T>(self, private: T) -> Result<JWTClaims<T>, InvalidJWTClaims> {
        if self.error {
            Err(InvalidJWTClaims)
        } else {
            Ok(JWTClaims {
                registered: self.registered,
                private,
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid JWT claims")]
pub struct InvalidJWTClaims;
