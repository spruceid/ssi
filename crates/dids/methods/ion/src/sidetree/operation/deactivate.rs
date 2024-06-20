use serde::{Deserialize, Serialize};

use crate::sidetree::{json_canonicalization_scheme, DIDSuffix, PublicKeyJwk, Sidetree};

use super::{jws_decode_verify_inner, PartialVerificationError, SidetreeOperation};

/// Sidetree DID Deactivate operation
///
/// ### References
/// - [Sidetree §11.4 Deactivate](https://identity.foundation/sidetree/spec/v1.0.0/#deactivate)
/// - [Sidetree REST API §1.2.4 Deactivate](https://identity.foundation/sidetree/api/#deactivate)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct DeactivateOperation {
    pub did_suffix: DIDSuffix,
    /// Output of [Sidetree::reveal_value]
    pub reveal_value: String,
    /// Compact JWS (RFC 7515) of [DeactivateClaims]
    ///
    /// <https://identity.foundation/sidetree/spec/v1.0.0/#deactivate-signed-data-object>
    pub signed_data: String,
}

impl SidetreeOperation for DeactivateOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedDeactivateOperation;

    /// Partially verify a [DeactivateOperation]
    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<PartiallyVerifiedDeactivateOperation, PartialVerificationError> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).

        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &DeactivateClaims| {
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

        if self.did_suffix != claims.did_suffix {
            return Err(PartialVerificationError::DIDSuffixMismatch);
        }

        Ok(PartiallyVerifiedDeactivateOperation {
            signed_did_suffix: claims.did_suffix,
            reveal_value: self.reveal_value,
            signed_recovery_key: claims.recovery_key,
        })
    }
}

/// Partially verified DID Deactivate operation
///
/// Converted from [DeactivateOperation].
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedDeactivateOperation {
    pub signed_did_suffix: DIDSuffix,
    pub reveal_value: String,
    pub signed_recovery_key: PublicKeyJwk,
}

/// Payload object for JWS in [DeactivateOperation]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct DeactivateClaims {
    pub did_suffix: DIDSuffix,
    /// Key matching previous Recovery Commitment
    pub recovery_key: PublicKeyJwk,
}
