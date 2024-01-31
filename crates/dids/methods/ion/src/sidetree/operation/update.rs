use serde::{Deserialize, Serialize};

use crate::sidetree::{json_canonicalization_scheme, DIDSuffix, Delta, PublicKeyJwk, Sidetree};

use super::{jws_decode_verify_inner, PartialVerificationError, SidetreeOperation};

/// Sidetree DID Update operation
///
/// ### References
/// - [Sidetree §11.2 Update](https://identity.foundation/sidetree/spec/v1.0.0/#update)
/// - [Sidetree REST API §1.2.2 Update](https://identity.foundation/sidetree/api/#update)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct UpdateOperation {
    pub did_suffix: DIDSuffix,
    /// Output of [Sidetree::reveal_value]
    pub reveal_value: String,
    pub delta: Delta,
    /// Compact JWS (RFC 7515) of [UpdateClaims]
    ///
    /// <https://identity.foundation/sidetree/spec/v1.0.0/#update-signed-data-object>
    pub signed_data: String,
}

/// Partially verified DID Create operation
///
/// Converted from [UpdateOperation].
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedUpdateOperation {
    pub reveal_value: String,
    pub signed_delta: Delta,
    pub signed_update_key: PublicKeyJwk,
}

impl SidetreeOperation for UpdateOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedUpdateOperation;

    /// Partially verify an [UpdateOperation]
    ///
    /// Specifically, the following is done:
    /// - The operation's [signed data](UpdateOperation::signed_data) is verified against the
    ///   revealed [public key](UpdateClaims::update_key) that it must contain;
    /// - the revealed public key is verified against the operation's
    ///   [reveal value](UpdateOperation::reveal_value); and
    /// - the operation's [delta object](UpdateOperation::delta) is verified against the
    ///   [delta hash](UpdateClaims::update_key) in the signed data payload.
    ///
    /// The [DID Suffix](UpdateOperation::did_suffix) is **not** verified
    /// by this function. The correspondence of the reveal value's hash to the previous update
    /// commitment is not checked either, since that is not known from this function.

    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<PartiallyVerifiedUpdateOperation, PartialVerificationError> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).
        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &UpdateClaims| {
                &claims.update_key
            })?;

        if header.algorithm != S::SIGNATURE_ALGORITHM {
            return Err(PartialVerificationError::InvalidSignatureAlgorithm);
        }

        let canonicalized_public_key = json_canonicalization_scheme(&claims.update_key).unwrap();
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
        Ok(PartiallyVerifiedUpdateOperation {
            reveal_value: self.reveal_value,
            signed_delta: self.delta,
            signed_update_key: claims.update_key,
        })
    }
}

/// Payload object for JWS in [UpdateOperation]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClaims {
    /// Key matching previous Update Commitment
    pub update_key: PublicKeyJwk,

    /// [Hash](Sidetree::hash) of canonicalized [Update Operation Delta Object](Delta).
    pub delta_hash: String,
}
