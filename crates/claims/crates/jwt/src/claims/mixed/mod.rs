use serde::Serialize;
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};
use ssi_jws::{JWSPayload, ValidateJWSHeader};
use std::borrow::Cow;

use super::{Claim, InfallibleClaimSet, RegisteredClaims};
use crate::{AnyClaims, ClaimSet};

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
    type Error = T::Error;

    fn contains<C: Claim>(&self) -> bool {
        ClaimSet::contains::<C>(&self.registered) || self.private.contains::<C>()
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, Self::Error> {
        match InfallibleClaimSet::get(&self.registered) {
            Some(claim) => Ok(Some(claim)),
            None => self.private.try_get(),
        }
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, Self::Error> {
        match InfallibleClaimSet::set(&mut self.registered, claim) {
            Ok(()) => Ok(Ok(())),
            Err(claim) => self.private.try_set(claim),
        }
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, Self::Error> {
        match InfallibleClaimSet::remove(&mut self.registered) {
            Some(claim) => Ok(Some(claim)),
            None => self.private.try_remove(),
        }
    }
}

impl<T: Serialize> JWSPayload for JWTClaims<T> {
    fn typ(&self) -> Option<&'static str> {
        Some("JWT")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<T, E> ValidateJWSHeader<E> for JWTClaims<T> {
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
