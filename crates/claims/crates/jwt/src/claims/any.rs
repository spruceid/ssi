use std::{borrow::Cow, collections::BTreeMap};

use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};

use crate::{Claim, ClaimSet, InfallibleClaimSet, InvalidClaimValue};

/// Any set of JWT claims.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AnyClaims(BTreeMap<String, serde_json::Value>);

impl AnyClaims {
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

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

impl FromIterator<(String, serde_json::Value)> for AnyClaims {
    fn from_iter<T: IntoIterator<Item = (String, serde_json::Value)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl ClaimSet for AnyClaims {
    fn contains<C: Claim>(&self) -> bool {
        self.contains(C::JWT_CLAIM_NAME)
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
        self.get(C::JWT_CLAIM_NAME)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
        self.set(C::JWT_CLAIM_NAME.to_owned(), serde_json::to_value(claim)?);
        Ok(Ok(()))
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
        self.remove(C::JWT_CLAIM_NAME)
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }
}

impl InfallibleClaimSet for AnyClaims {}

impl<E, P> ValidateClaims<E, P> for AnyClaims
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ClaimsValidity {
        ClaimSet::validate_registered_claims(self, env)
    }
}
