//! JWT encoding of a Status Lists.
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_jwt::{NumericDate, StringOrURI};

use crate::{StatusList, StatusSize};

/// Status List JWT.
/// 
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token>
#[derive(Serialize, Deserialize)]
pub struct StatusListJwt {
    /// Issuer (`iss`) claim.
    ///
    /// Principal that issued the JWT. The processing of this claim is generally
    /// application specific.
    #[serde(rename = "iss")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<StringOrURI>,

    /// Subject (`sub`) claim.
    ///
    /// Principal that is the subject of the JWT. The claims in a JWT are
    /// normally statements about the subject. The subject value MUST either be
    /// scoped to be locally unique in the context of the issuer or be globally
    /// unique.
    ///
    /// The processing of this claim is generally application specific.
    #[serde(rename = "sub")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<StringOrURI>,

    /// Expiration Time (`exp`) claim.
    ///
    /// Expiration time on or after which the JWT MUST NOT be accepted for
    /// processing. The processing of the `exp` claim requires that the current
    /// date/time MUST be before the expiration date/time listed in the `exp`
    /// claim.
    #[serde(rename = "exp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<NumericDate>,

    /// Issued At (`iat`) claim.
    ///
    /// Time at which the JWT was issued. This claim can be used to determine
    /// the age of the JWT.
    #[serde(rename = "iat")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<NumericDate>,

    /// Time to live.
    ///
    /// Maximum amount of time, in seconds, that the Status List Token can be
    /// cached by a consumer before a fresh copy *should* be retrieved. The
    /// value of the claim *must* be a positive number.
    #[serde(rename = "ttl")]
    pub time_to_live: Option<u64>,

    /// Status list.
    #[serde(serialize_with = "serialize_status_list", deserialize_with = "deserialize_status_list")]
    pub status_list: StatusList,

    /// Other claims not directly related to status lists.
    #[serde(flatten)]
    pub other_claims: ssi_jwt::Claims
}

fn serialize_status_list<S: serde::Serializer>(list: &StatusList, serializer: S) -> Result<S::Ok, S::Error> {
    let lst = base64::encode_config(list.as_bytes(), base64::URL_SAFE);
    JsonStatusList {
        bits: list.status_size(),
        lst
    }.serialize(serializer)
}

fn deserialize_status_list<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<StatusList, D::Error> {
    let json = JsonStatusList::deserialize(deserializer)?;
    let bytes = base64::decode_config(&json.lst, base64::URL_SAFE)
        .map_err( serde::de::Error::custom)?;
    Ok(StatusList::from_parts(json.bits, bytes))
}

/// JSON Status List.
/// 
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list>
#[derive(Serialize, Deserialize)]
pub struct JsonStatusList {
    /// Number of bits per Referenced Token in `lst`.
    bits: StatusSize,

    /// Status values for all the Referenced Tokens it conveys statuses for.
    lst: String
}

/// Status claim value.
#[derive(Serialize, Deserialize)]
pub struct Status {
    pub status_list: StatusListReference
}

#[derive(Serialize, Deserialize)]
pub struct StatusListReference {
    /// Index to check for status information in the Status List for the current
    /// Referenced Token.
    pub idx: usize,

    /// Identifies the Status List or Status List Token containing the status
    /// information for the Referenced Token.
    pub uri: UriBuf
}