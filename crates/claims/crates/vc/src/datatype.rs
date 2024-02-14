use core::fmt;
use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

/// RFC3339 date-time as used in VC Data Model
/// <https://www.w3.org/TR/vc-data-model/#issuance-date>
/// <https://www.w3.org/TR/vc-data-model/#expiration>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct VCDateTime {
    /// The date-time
    date_time: DateTime<FixedOffset>,
    /// Whether to use "Z" or "+00:00" when formatting the date-time in UTC
    use_z: bool,
}

impl VCDateTime {
    pub fn new(date_time: DateTime<FixedOffset>, use_z: bool) -> Self {
        Self { date_time, use_z }
    }
}

impl FromStr for VCDateTime {
    type Err = chrono::format::ParseError;
    fn from_str(date_time: &str) -> Result<Self, Self::Err> {
        let use_z = date_time.ends_with('Z');
        let date_time = DateTime::parse_from_rfc3339(date_time)?;
        Ok(VCDateTime { date_time, use_z })
    }
}

impl TryFrom<String> for VCDateTime {
    type Error = chrono::format::ParseError;
    fn try_from(date_time: String) -> Result<Self, Self::Error> {
        Self::from_str(&date_time)
    }
}

impl fmt::Display for VCDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.date_time
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, self.use_z)
            .fmt(f)
    }
}

impl From<VCDateTime> for String {
    fn from(z_date_time: VCDateTime) -> String {
        let VCDateTime { date_time, use_z } = z_date_time;
        date_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, use_z)
    }
}

impl<Tz: chrono::TimeZone> From<DateTime<Tz>> for VCDateTime
where
    chrono::DateTime<chrono::FixedOffset>: From<chrono::DateTime<Tz>>,
{
    fn from(date_time: DateTime<Tz>) -> Self {
        Self {
            date_time: date_time.into(),
            use_z: true,
        }
    }
}

impl<Tz: chrono::TimeZone> From<VCDateTime> for DateTime<Tz>
where
    chrono::DateTime<Tz>: From<chrono::DateTime<chrono::FixedOffset>>,
{
    fn from(vc_date_time: VCDateTime) -> Self {
        Self::from(vc_date_time.date_time)
    }
}
