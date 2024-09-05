//! JWT encoding of a Status Lists.
use std::borrow::Cow;

use base64::prelude::{Engine, BASE64_URL_SAFE};
use flate2::Compression;
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_claims_core::ValidateClaims;
use ssi_jws::ValidateJwsHeader;
use ssi_jwt::{
    match_claim_type, AnyClaims, Claim, ClaimSet, InvalidClaimValue, IssuedAt, Issuer, JWTClaims,
    Subject,
};

use crate::{
    token_status_list::{BitString, StatusSize},
    StatusMapEntry, StatusMapEntrySet,
};

use super::{DecodeError, StatusList};

/// Status List JWT.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token>
pub type StatusListJwt = JWTClaims<StatusListJwtPrivateClaims>;

pub fn decode_status_list_jwt(mut claims: impl ClaimSet) -> Result<StatusList, DecodeError> {
    let _ = claims
        .try_remove::<Issuer>()
        .map_err(DecodeError::claim)?
        .ok_or(DecodeError::MissingIssuer)?;

    let _ = claims
        .try_remove::<Subject>()
        .map_err(DecodeError::claim)?
        .ok_or(DecodeError::MissingSubject)?;

    let _ = claims
        .try_remove::<IssuedAt>()
        .map_err(DecodeError::claim)?
        .ok_or(DecodeError::MissingSubject)?;
    let ttl = claims
        .try_remove()
        .map_err(DecodeError::claim)?
        .map(TimeToLiveClaim::unwrap);

    let bit_string = claims
        .try_remove::<JsonStatusList>()
        .map_err(DecodeError::claim)?
        .ok_or(DecodeError::MissingStatusList)?
        .decode(None)?;

    Ok(StatusList::new(bit_string, ttl))
}

/// Status List JWT private claims.
///
/// This includes status list specific claims such as `ttl` and `status_list`,
/// but also all the extra claims unrelated to status lists.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token>
#[derive(Serialize, Deserialize)]
pub struct StatusListJwtPrivateClaims {
    /// Time to live.
    ///
    /// Maximum amount of time, in seconds, that the Status List Token can be
    /// cached by a consumer before a fresh copy *should* be retrieved. The
    /// value of the claim *must* be a positive number.
    #[serde(rename = "ttl")]
    pub time_to_live: Option<TimeToLiveClaim>,

    /// Status list.
    pub status_list: Option<JsonStatusList>,

    /// Other claims.
    #[serde(flatten)]
    pub other_claims: AnyClaims,
}

impl ClaimSet for StatusListJwtPrivateClaims {
    fn contains<C: Claim>(&self) -> bool {
        match_claim_type! {
            match C {
                TimeToLiveClaim => self.time_to_live.is_some(),
                JsonStatusList => self.status_list.is_some(),
                _ => ClaimSet::contains::<C>(&self.other_claims)
            }
        }
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
        match_claim_type! {
            match C {
                TimeToLiveClaim => {
                    Ok(self.time_to_live.as_ref().map(Cow::Borrowed))
                },
                JsonStatusList => {
                    Ok(self.status_list.as_ref().map(Cow::Borrowed))
                },
                _ => {
                    self.other_claims.try_get()
                }
            }
        }
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
        match_claim_type! {
            match claim: C {
                TimeToLiveClaim => {
                    self.time_to_live = Some(claim);
                    Ok(Ok(()))
                },
                JsonStatusList => {
                    self.status_list = Some(claim);
                    Ok(Ok(()))
                },
                _ => {
                    self.other_claims.try_set(claim)
                }
            }
        }
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
        match_claim_type! {
            match C {
                TimeToLiveClaim => {
                    Ok(self.time_to_live.take())
                },
                JsonStatusList => {
                    Ok(self.status_list.take())
                },
                _ => {
                    self.other_claims.try_remove()
                }
            }
        }
    }
}

impl<E, P> ValidateClaims<E, P> for StatusListJwtPrivateClaims {
    fn validate_claims(&self, _env: &E, _proof: &P) -> ssi_claims_core::ClaimsValidity {
        Ok(())
    }
}

impl<E> ValidateJwsHeader<E> for StatusListJwtPrivateClaims {
    fn validate_jws_header(
        &self,
        _env: &E,
        _header: &ssi_jws::Header,
    ) -> ssi_claims_core::ClaimsValidity {
        Ok(())
    }
}

/// Time to live JWT claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeToLiveClaim(pub u64);

impl TimeToLiveClaim {
    pub fn unwrap(self) -> u64 {
        self.0
    }
}

impl Claim for TimeToLiveClaim {
    const JWT_CLAIM_NAME: &'static str = "ttl";
}

/// JSON Status List.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list>
#[derive(Clone, Serialize, Deserialize)]
pub struct JsonStatusList {
    /// Number of bits per Referenced Token in `lst`.
    bits: StatusSize,

    /// Status values for all the Referenced Tokens it conveys statuses for.
    lst: String,
}

impl JsonStatusList {
    pub fn encode(bit_string: &BitString, compression: Compression) -> Self {
        let bytes = bit_string.to_compressed_bytes(compression);
        Self {
            bits: bit_string.status_size(),
            lst: BASE64_URL_SAFE.encode(bytes),
        }
    }

    pub fn decode(&self, limit: Option<u64>) -> Result<BitString, DecodeError> {
        let bytes = BASE64_URL_SAFE.decode(&self.lst)?;
        Ok(BitString::from_compressed_bytes(self.bits, &bytes, limit)?)
    }
}

impl Claim for JsonStatusList {
    const JWT_CLAIM_NAME: &'static str = "status_list";
}

/// Status claim value.
#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
    pub status_list: StatusListReference,
}

impl Claim for Status {
    const JWT_CLAIM_NAME: &'static str = "status";
}

impl StatusMapEntrySet for Status {
    type Entry<'a> = &'a StatusListReference;

    fn get_entry(&self, _purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        Some(&self.status_list)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StatusListReference {
    /// Index to check for status information in the Status List for the current
    /// Referenced Token.
    pub idx: usize,

    /// Identifies the Status List or Status List Token containing the status
    /// information for the Referenced Token.
    pub uri: UriBuf,
}

impl StatusMapEntry for StatusListReference {
    type Key = usize;
    type StatusSize = StatusSize;

    fn key(&self) -> Self::Key {
        self.idx
    }

    fn status_list_url(&self) -> &iref::Uri {
        &self.uri
    }

    fn status_size(&self) -> Option<Self::StatusSize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::token_status_list::json::JsonStatusList;

    #[test]
    fn deserialize_json_status_list() {
        assert!(serde_json::from_str::<JsonStatusList>(
            r#"{
                "bits": 1,
                "lst": "eNrbuRgAAhcBXQ"
            }"#
        )
        .is_ok())
    }
}
