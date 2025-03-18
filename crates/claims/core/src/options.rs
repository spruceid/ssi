use chrono::{DateTime, Utc};

pub use ssi_crypto::Options;

pub struct CurrentDateTime(pub DateTime<Utc>);

pub trait GetCurrentDataTime {
    fn date_time(&self) -> DateTime<Utc>;
}

impl GetCurrentDataTime for Options {
    fn date_time(&self) -> DateTime<Utc> {
        match self.get() {
            Some(CurrentDateTime(now)) => *now,
            None => Utc::now(),
        }
    }
}
