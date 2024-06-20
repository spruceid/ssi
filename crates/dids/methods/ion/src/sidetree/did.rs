use core::fmt;
use std::{marker::PhantomData, str::FromStr};

use serde::{Deserialize, Serialize};
use ssi_dids_core::registration::DIDTransactionCreationError;

use super::{InvalidSidetreeDIDSuffix, Sidetree};

/// A Sidetree-based DID
///
/// Reference: [Sidetree §9. DID URI Composition][duc]
///
/// [duc]: https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition
pub enum SidetreeDID<S: Sidetree> {
    /// Short-form Sidetree DID
    ///
    /// Reference: [§9. DID URI Composition](https://identity.foundation/sidetree/spec/v1.0.0/#short-form-did)
    Short { did_suffix: DIDSuffix },

    /// Long-form Sidetree DID
    ///
    /// Reference: [§9.1 Long-Form DID URIs](https://identity.foundation/sidetree/spec/v1.0.0/#long-form-did-uris)
    Long {
        did_suffix: DIDSuffix,
        create_operation_data: String,
        _marker: PhantomData<S>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidSidetreeDID {
    #[error("invalid URI scheme")]
    InvalidURIScheme,

    #[error("DID method mismatch")]
    DIDMethodMismatch,

    #[error("Sidetree network mismatch")]
    SidetreeNetworkMismatch,

    #[error("missing sidetree DID suffix")]
    MissingSidetreeDIDSuffix,

    #[error(transparent)]
    InvalidSidetreeDIDSuffix(#[from] InvalidSidetreeDIDSuffix),

    #[error("unexpected data after Sidetree Long-Form DID")]
    UnexpectedData,
}

impl<S: Sidetree> FromStr for SidetreeDID<S> {
    type Err = InvalidSidetreeDID;

    fn from_str(did: &str) -> Result<Self, Self::Err> {
        let mut parts = did.split(':');

        if parts.next() != Some("did") {
            return Err(InvalidSidetreeDID::InvalidURIScheme);
        }

        if parts.next() != Some(S::METHOD) {
            return Err(InvalidSidetreeDID::DIDMethodMismatch);
        }

        if let Some(network) = S::NETWORK {
            if parts.next() != Some(network) {
                return Err(InvalidSidetreeDID::SidetreeNetworkMismatch);
            }
        }

        let did_suffix_str = parts
            .next()
            .ok_or(InvalidSidetreeDID::MissingSidetreeDIDSuffix)?;
        let did_suffix = DIDSuffix(did_suffix_str.to_string());
        S::validate_did_suffix(&did_suffix)?;
        let create_operation_data_opt = parts.next();
        if parts.next().is_some() {
            return Err(InvalidSidetreeDID::UnexpectedData);
        }
        Ok(match create_operation_data_opt {
            None => Self::Short { did_suffix },
            Some(data) => Self::Long {
                did_suffix,
                create_operation_data: data.to_string(),
                _marker: PhantomData,
            },
        })
    }
}

impl<S: Sidetree> fmt::Display for SidetreeDID<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "did:{}:", S::METHOD)?;
        if let Some(network) = S::NETWORK {
            write!(f, "{}:", network)?;
        }
        match self {
            Self::Short { did_suffix } => f.write_str(&did_suffix.0),
            Self::Long {
                did_suffix,
                create_operation_data,
                _marker,
            } => write!(f, "{}:{}", did_suffix.0, create_operation_data),
        }
    }
}

impl From<InvalidSidetreeDID> for DIDTransactionCreationError {
    fn from(_value: InvalidSidetreeDID) -> Self {
        DIDTransactionCreationError::InvalidDID
    }
}

/// [DID Suffix](https://identity.foundation/sidetree/spec/v1.0.0/#did-suffix)
///
/// Unique identifier string within a Sidetree DID (short or long-form)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DIDSuffix(pub String);

impl fmt::Display for DIDSuffix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)?;
        Ok(())
    }
}

impl<S: Sidetree> From<SidetreeDID<S>> for DIDSuffix {
    fn from(did: SidetreeDID<S>) -> DIDSuffix {
        match did {
            SidetreeDID::Short { did_suffix } => did_suffix,
            SidetreeDID::Long { did_suffix, .. } => did_suffix,
        }
    }
}
