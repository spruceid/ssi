mod registered;
use std::borrow::Cow;

use chrono::Utc;
pub use registered::*;
mod mixed;
pub use mixed::*;
mod matching;
pub use matching::*;
mod any;
pub use any::*;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, InvalidClaims};

#[derive(Debug, thiserror::Error)]
#[error("invalid claim value")]
pub struct InvalidClaimValue(String);

impl InvalidClaimValue {
    pub fn new(e: impl ToString) -> Self {
        Self(e.to_string())
    }
}

impl From<serde_json::Error> for InvalidClaimValue {
    fn from(value: serde_json::Error) -> Self {
        Self::new(value)
    }
}

/// JWT claim.
pub trait Claim: 'static + Clone + Serialize + DeserializeOwned {
    /// Claim name, used as key in the JSON representation.
    const JWT_CLAIM_NAME: &'static str;
}

pub trait ClaimSet {
    fn contains<C: Claim>(&self) -> bool {
        false
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
        Ok(None)
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
        Ok(Err(claim))
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
        Ok(None)
    }

    fn validate_registered_claims<E>(&self, env: &E) -> ClaimsValidity
    where
        E: DateTimeProvider,
    {
        let now = env.date_time();

        if let Some(iat) = self.try_get::<IssuedAt>().map_err(InvalidClaims::other)? {
            let valid_from: chrono::DateTime<Utc> = iat.0.into();
            if valid_from > now {
                return Err(InvalidClaims::Premature { now, valid_from });
            }
        }

        if let Some(nbf) = self.try_get::<NotBefore>().map_err(InvalidClaims::other)? {
            let valid_from: chrono::DateTime<Utc> = nbf.0.into();
            if valid_from > now {
                return Err(InvalidClaims::Premature { now, valid_from });
            }
        }

        if let Some(exp) = self
            .try_get::<ExpirationTime>()
            .map_err(InvalidClaims::other)?
        {
            let valid_until: chrono::DateTime<Utc> = exp.0.into();
            if valid_until <= now {
                return Err(InvalidClaims::Expired { now, valid_until });
            }
        }

        Ok(())
    }
}

/// Set of JWT claims.
pub trait InfallibleClaimSet: ClaimSet {
    fn get<C: Claim>(&self) -> Option<Cow<C>> {
        Self::try_get(self).unwrap()
    }

    fn set<C: Claim>(&mut self, claim: C) -> Result<(), C> {
        Self::try_set(self, claim).unwrap()
    }

    fn remove<C: Claim>(&mut self) -> Option<C> {
        Self::try_remove(self).unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimKind<U = String> {
    Registered(RegisteredClaimKind),
    Unregistered(U),
}

impl ClaimKind {
    pub fn as_ref(&self) -> ClaimKind<&str> {
        match self {
            Self::Registered(r) => ClaimKind::Registered(*r),
            Self::Unregistered(u) => ClaimKind::Unregistered(u),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ClaimKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        match RegisteredClaimKind::new(&name) {
            Some(r) => Ok(Self::Registered(r)),
            None => Ok(Self::Unregistered(name)),
        }
    }
}

impl<'a> ClaimKind<&'a str> {
    pub fn into_owned(self) -> ClaimKind {
        match self {
            Self::Registered(r) => ClaimKind::Registered(r),
            Self::Unregistered(u) => ClaimKind::Unregistered(u.to_owned()),
        }
    }
}

impl hashbrown::Equivalent<ClaimKind<String>> for ClaimKind<&str> {
    fn equivalent(&self, key: &ClaimKind<String>) -> bool {
        *self == key.as_ref()
    }
}
