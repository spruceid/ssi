use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::sidetree::{json_canonicalization_scheme, DIDSuffix, Delta, Sidetree, SidetreeDID};

use super::{PartialVerificationError, SidetreeOperation};

/// Sidetree DID Create operation
///
/// ### References
/// - [Sidetree §11.1 Create](https://identity.foundation/sidetree/spec/v1.0.0/#create)
/// - [Sidetree REST API §1.2.1 Create](https://identity.foundation/sidetree/api/#create)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CreateOperation {
    pub suffix_data: SuffixData,
    pub delta: Delta,
}

impl CreateOperation {
    /// Construct a [Long-Form Sidetree DID][lfdu] from a [Create Operation][CreateOperation]
    ///
    /// [lfdu]: https://identity.foundation/sidetree/spec/v1.0.0/#long-form-did-uris
    pub fn to_sidetree_did<S: Sidetree>(&self) -> SidetreeDID<S> {
        let op_json = json_canonicalization_scheme(self).unwrap();
        // .context("Canonicalize Create Operation")?;
        let op_string = S::data_encoding_scheme(op_json.as_bytes());

        let did_suffix = S::serialize_suffix_data(&self.suffix_data);
        // .context("Serialize DID Suffix Data")?;
        SidetreeDID::Long {
            did_suffix,
            create_operation_data: op_string,
            _marker: PhantomData,
        }
    }
}

impl SidetreeOperation for CreateOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedCreateOperation;

    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<PartiallyVerifiedCreateOperation, PartialVerificationError> {
        let did: SidetreeDID<S> = self.to_sidetree_did();
        let did_suffix = DIDSuffix::from(did);
        let delta_string = json_canonicalization_scheme(&self.delta).unwrap();
        let delta_hash = S::hash(delta_string.as_bytes());

        if delta_hash != self.suffix_data.delta_hash {
            return Err(PartialVerificationError::DeltaHashMismatch);
        }

        Ok(PartiallyVerifiedCreateOperation {
            did_suffix,
            r#type: self.suffix_data.r#type,
            recovery_commitment: self.suffix_data.recovery_commitment,
            anchor_origin: self.suffix_data.anchor_origin,
            hashed_delta: self.delta,
        })
    }
}

/// Partially verified DID Create operation
///
/// Converted from [CreateOperation].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedCreateOperation {
    pub did_suffix: DIDSuffix,
    pub r#type: Option<String>,
    pub recovery_commitment: String,
    pub anchor_origin: Option<String>,
    pub hashed_delta: Delta,
}

/// [Create Operation Suffix Data Object][data]
///
/// [data]: https://identity.foundation/sidetree/spec/v1.0.0/#create-suffix-data-object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SuffixData {
    /// Implementation-defined type property
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// Delta Hash
    ///
    /// [Hash](Sidetree::hash) of canonicalized [Create Operation Delta Object](Delta).
    pub delta_hash: String,

    /// [Recovery commitment](https://identity.foundation/sidetree/spec/v1.0.0/#recovery-commitment)
    ///
    /// Generated in step 2 of the [Create](https://identity.foundation/sidetree/spec/v1.0.0/#create) process.
    pub recovery_commitment: String,

    /// Anchor Origin
    ///
    /// Implementation-defined identifier for most recent anchor for the DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_origin: Option<String>,
    // TODO: extensible by method
}
