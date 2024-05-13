use std::{borrow::Cow, collections::BTreeMap};

use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, Validate};
use ssi_jws::JWSPayload;

use crate::{GetClaim, PrivateClaimSet, RemoveClaim, SetClaim, TryRemoveClaim, TrySetClaim};

use super::{Claim, ClaimSet, RegisteredClaims, TryGetClaim};

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
}

impl<T: Serialize> JWSPayload for JWTClaims<T> {
    fn typ(&self) -> Option<&'static str> {
        Some("JWT")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<C: Claim, T: ClaimSet> TryGetClaim<C> for JWTClaims<T>
where
    T: TryGetClaim<C::Private>,
{
    fn try_get_claim(&self) -> Result<Option<Cow<C>>, Self::Error> {
        if C::IS_REGISTERED_JWT_CLAIM {
            Ok(self
                .registered
                .get::<C::Registered>()
                .map(|value| Cow::Borrowed(C::from_registered_ref(value).unwrap())))
        } else {
            self.private
                .try_get_claim()
                .map(|r| r.map(|value| C::from_private_cow(value).unwrap()))
        }
    }
}

impl<C: Claim, T: ClaimSet> GetClaim<C> for JWTClaims<T>
where
    T: GetClaim<C::Private>,
{
    fn get_claim(&self) -> Option<Cow<C>> {
        if C::IS_REGISTERED_JWT_CLAIM {
            self.registered
                .get::<C::Registered>()
                .map(|value| Cow::Borrowed(C::from_registered_ref(value).unwrap()))
        } else {
            self.private
                .get_claim()
                .map(|value| C::from_private_cow(value).unwrap())
        }
    }
}

impl<C: Claim, T: ClaimSet> TrySetClaim<C> for JWTClaims<T>
where
    T: TrySetClaim<C::Private>,
{
    fn try_set_claim(&mut self, claim: C) -> Result<(), Self::Error> {
        match claim.into_registered() {
            Ok(claim) => {
                self.registered.set(claim);
                Ok(())
            }
            Err(claim) => self.private.try_set(claim),
        }
    }
}

impl<C: Claim, T: ClaimSet> SetClaim<C> for JWTClaims<T>
where
    T: SetClaim<C::Private>,
{
    fn set_claim(&mut self, claim: C) {
        match claim.into_registered() {
            Ok(claim) => {
                self.registered.set(claim);
            }
            Err(claim) => self.private.set(claim),
        }
    }
}

impl<C: Claim, T: ClaimSet> TryRemoveClaim<C> for JWTClaims<T>
where
    T: TryRemoveClaim<C::Private>,
{
    fn try_remove_claim(&mut self) -> Result<Option<C>, Self::Error> {
        if C::IS_REGISTERED_JWT_CLAIM {
            Ok(self
                .registered
                .remove::<C::Registered>()
                .map(|value| C::from_registered(value).unwrap()))
        } else {
            self.private
                .try_remove_claim()
                .map(|r| r.map(|value| C::from_private(value).unwrap()))
        }
    }
}

impl<C: Claim, T: ClaimSet> RemoveClaim<C> for JWTClaims<T>
where
    T: RemoveClaim<C::Private>,
{
    fn remove_claim(&mut self) -> Option<C> {
        if C::IS_REGISTERED_JWT_CLAIM {
            self.registered
                .remove::<C::Registered>()
                .map(|value| C::from_registered(value).unwrap())
        } else {
            self.private
                .remove_claim()
                .map(|value| C::from_private(value).unwrap())
        }
    }
}

impl<T: ClaimSet + Validate<E>, E> Validate<E> for JWTClaims<T>
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E) -> ClaimsValidity {
        self.registered.validate(env)?;
        self.private.validate(env)
    }
}

/// Any set of JWT claims.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AnyClaims(BTreeMap<String, serde_json::Value>);

impl AnyClaims {
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    pub fn set(&mut self, key: String, value: serde_json::Value) -> Option<serde_json::Value> {
        self.0.insert(key, value)
    }

    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.0.remove(key)
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<String, serde_json::Value> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a AnyClaims {
    type IntoIter = std::collections::btree_map::Iter<'a, String, serde_json::Value>;
    type Item = (&'a String, &'a serde_json::Value);

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for AnyClaims {
    type IntoIter = std::collections::btree_map::IntoIter<String, serde_json::Value>;
    type Item = (String, serde_json::Value);

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl PrivateClaimSet for AnyClaims {
    type Error = serde_json::Error;
}

impl<C: Claim + DeserializeOwned> TryGetClaim<C> for AnyClaims {
    fn try_get_claim(&self) -> Result<Option<Cow<C>>, Self::Error> {
        match self.0.get(C::JWT_CLAIM_NAME) {
            Some(value) => serde_json::from_value(value.clone()).map(|t| Some(Cow::Owned(t))),
            None => Ok(None),
        }
    }
}

impl<C: Claim + Serialize> TrySetClaim<C> for AnyClaims {
    fn try_set_claim(&mut self, claim: C) -> Result<(), Self::Error> {
        self.0
            .insert(C::JWT_CLAIM_NAME.to_owned(), serde_json::to_value(claim)?);
        Ok(())
    }
}

impl<C: Claim + DeserializeOwned> TryRemoveClaim<C> for AnyClaims {
    fn try_remove_claim(&mut self) -> Result<Option<C>, Self::Error> {
        match self.0.remove(C::JWT_CLAIM_NAME) {
            Some(value) => serde_json::from_value(value).map(Some),
            None => Ok(None),
        }
    }
}

impl<E> Validate<E> for AnyClaims
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E) -> ClaimsValidity {
        ClaimSet::validate_registered_claims(self, env)
    }
}
