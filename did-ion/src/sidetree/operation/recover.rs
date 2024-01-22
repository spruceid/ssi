use serde::{Deserialize, Serialize};

use crate::sidetree::{json_canonicalization_scheme, DIDSuffix, Delta, PublicKeyJwk, Sidetree};

use super::{jws_decode_verify_inner, PartialVerificationError, SidetreeOperation};

/// Sidetree DID Recover operation
///
/// ### References
/// - [Sidetree §11.3 Recover](https://identity.foundation/sidetree/spec/v1.0.0/#recover)
/// - [Sidetree REST API §1.2.3 Recover](https://identity.foundation/sidetree/api/#recover)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RecoverOperation {
    pub did_suffix: DIDSuffix,
    /// Output of [Sidetree::reveal_value]
    pub reveal_value: String,
    pub delta: Delta,
    /// Compact JWS (RFC 7515) of [RecoveryClaims]
    ///
    /// <https://identity.foundation/sidetree/spec/v1.0.0/#recover-signed-data-object>
    pub signed_data: String,
}

impl SidetreeOperation for RecoverOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedRecoverOperation;

    /// Partially verify a [RecoverOperation]
    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<PartiallyVerifiedRecoverOperation, PartialVerificationError> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).
        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &RecoveryClaims| {
                &claims.recovery_key
            })?;

        if header.algorithm != S::SIGNATURE_ALGORITHM {
            return Err(PartialVerificationError::InvalidSignatureAlgorithm);
        }

        let canonicalized_public_key = json_canonicalization_scheme(&claims.recovery_key).unwrap();
        let computed_reveal_value = S::reveal_value(canonicalized_public_key.as_bytes());
        if self.reveal_value != computed_reveal_value {
            return Err(PartialVerificationError::RevealValueMismatch {
                computed: computed_reveal_value,
                found: self.reveal_value,
            });
        }
        let delta_string = json_canonicalization_scheme(&self.delta).unwrap();
        let delta_hash = S::hash(delta_string.as_bytes());
        if claims.delta_hash != delta_hash {
            return Err(PartialVerificationError::DeltaHashMismatch);
        }
        // Note: did_suffix is dropped, since it's not signed over.
        Ok(PartiallyVerifiedRecoverOperation {
            reveal_value: self.reveal_value,
            signed_delta: self.delta,
            signed_recovery_commitment: claims.recovery_commitment,
            signed_recovery_key: claims.recovery_key,
            signed_anchor_origin: claims.anchor_origin,
        })
    }
}

/// Partially verified DID Recovery operation
///
/// Converted from [RecoverOperation].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedRecoverOperation {
    pub reveal_value: String,
    pub signed_delta: Delta,
    pub signed_recovery_commitment: String,
    pub signed_recovery_key: PublicKeyJwk,
    pub signed_anchor_origin: Option<String>,
}

/// Payload object for JWS in [RecoverOperation]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryClaims {
    /// [Recovery commitment](https://identity.foundation/sidetree/spec/v1.0.0/#recovery-commitment)
    ///
    /// Generated in step 9 of the [Recover](https://identity.foundation/sidetree/spec/v1.0.0/#recover) process.
    pub recovery_commitment: String,

    /// Key matching previous Recovery Commitment
    pub recovery_key: PublicKeyJwk,

    /// [Hash](Sidetree::hash) of canonicalized [Update Operation Delta Object](Delta).
    pub delta_hash: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_origin: Option<String>,
}
