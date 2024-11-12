use crate::log::{parameters::Parameters, version_id::VersionId};
use chrono::{DateTime, Utc};
use ssi_data_integrity::AnyProofs;
use ssi_dids_core::document::Document;

pub struct Entry {
    version_id: VersionId,
    version_time: DateTime<Utc>,
    parameters: Parameters,
    state: Document,
    proof: AnyProofs,
}

impl Entry {
    pub fn new(
        version_id: VersionId,
        version_time: DateTime<Utc>,
        parameters: Parameters,
        state: Document,
        proof: AnyProofs,
    ) -> Self {
        Self {
            version_id,
            version_time,
            parameters,
            state,
            proof,
        }
    }

    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    pub fn version_time(&self) -> &DateTime<Utc> {
        &self.version_time
    }

    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    pub fn state(&self) -> &Document {
        &self.state
    }

    pub fn proof(&self) -> &AnyProofs {
        &self.proof
    }
}
