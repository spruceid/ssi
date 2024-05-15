use std::{borrow::Cow, collections::BTreeMap};

use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, Proof, Validate};

use crate::{Claim, ClaimSet};

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

impl ClaimSet for AnyClaims {
    type Error = serde_json::Error;

    fn contains<C: Claim>(&self) -> bool {
        self.contains(C::JWT_CLAIM_NAME)
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, Self::Error> {
        self.get(C::JWT_CLAIM_NAME)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, Self::Error> {
        self.set(C::JWT_CLAIM_NAME.to_owned(), serde_json::to_value(claim)?);
        Ok(Ok(()))
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, Self::Error> {
        self.remove(C::JWT_CLAIM_NAME)
            .map(serde_json::from_value)
            .transpose()
    }
}

impl<E, P: Proof> Validate<E, P> for AnyClaims
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E, _proof: &P::Prepared) -> ClaimsValidity {
        ClaimSet::validate_registered_claims(self, env)
    }
}
