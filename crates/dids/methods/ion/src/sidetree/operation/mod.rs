mod create;
mod deactivate;
mod recover;
mod update;

pub use create::*;
pub use deactivate::*;
pub use recover::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::DecodedSigningBytes;
pub use update::*;

use super::{
    json_canonicalization_scheme, DIDSuffix, JWKFromPublicKeyJwkError, PublicKeyJwk, Sidetree,
};

/// Sidetree DID operation
///
/// ### References
/// - <https://identity.foundation/sidetree/spec/v1.0.0/#did-operations>
/// - <https://identity.foundation/sidetree/spec/v1.0.0/#sidetree-operations>
/// - <https://identity.foundation/sidetree/api/#sidetree-operations>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum Operation {
    Create(CreateOperation),
    Update(UpdateOperation),
    Recover(RecoverOperation),
    Deactivate(DeactivateOperation),
}

#[derive(Debug, thiserror::Error)]
pub enum OperationFromTransactionError {
    #[error("missing `sidetreeOperation` property")]
    MissingSidetreeOperation,

    #[error("invalid `sidetreeOperation` value")]
    InvalidSidetreeOperation,
}

impl Operation {
    pub fn from_transaction(
        mut transaction: serde_json::Value,
    ) -> Result<Self, OperationFromTransactionError> {
        let op_value = transaction
            .as_object_mut()
            .ok_or(OperationFromTransactionError::MissingSidetreeOperation)?
            .remove("sidetreeOperation")
            .ok_or(OperationFromTransactionError::MissingSidetreeOperation)?;
        let op: Operation = serde_json::from_value(op_value)
            .map_err(|_| OperationFromTransactionError::InvalidSidetreeOperation)?;
        Ok(op)
    }

    pub fn into_transaction(self) -> serde_json::Value {
        let value = serde_json::to_value(self).unwrap();
        serde_json::json!({ "sidetreeOperation": value })
    }
}

/// Partially verified Sidetree DID operation
///
/// Converted from [Operation].
///
/// Operation verification is described in [Sidetree §10.2.1 Operation Verification][ov].
///
/// [ov]: https://identity.foundation/sidetree/spec/v1.0.0/#operation-verification
#[derive(Debug, Clone)]
pub enum PartiallyVerifiedOperation {
    Create(PartiallyVerifiedCreateOperation),
    Update(PartiallyVerifiedUpdateOperation),
    Recover(PartiallyVerifiedRecoverOperation),
    Deactivate(PartiallyVerifiedDeactivateOperation),
}

#[derive(Debug, thiserror::Error)]
pub enum PartialVerificationError {
    #[error("invalid signature algorithm")]
    InvalidSignatureAlgorithm,

    #[error("reveal value mismatch (computed: {computed:?}, found: {found:?})")]
    RevealValueMismatch { computed: String, found: String },

    #[error("delta hash mismatch")]
    DeltaHashMismatch,

    #[error("DID suffix mismatch")]
    DIDSuffixMismatch,

    #[error(transparent)]
    JWSDecodeVerifyError(#[from] JWSDecodeVerifyError),
}

/// A Sidetree operation
///
/// See also the enum [Operation] which implements this trait.
pub trait SidetreeOperation {
    /// The result of [partially verifying][Self::partial_verify] the operation.
    type PartiallyVerifiedForm;

    /// Partially verify the operation.
    ///
    /// Operation verification is described in [Sidetree §10.2.1 Operation Verification][ov].
    ///
    /// This function verifies the internal consistency (including signatures and hashes) of the operation,
    /// and returns the integrity-verified data.
    /// Public key commitment values are not checked; that is, the signature is verified, but
    /// whether the public key is the correct reveal value is not checked, since that depends on
    /// what the previous operation was. The DID suffix is also not checked, except for a Create
    /// operation, since it is otherwise in reference to an earlier (Create) opeation.
    ///
    /// [ov]: https://identity.foundation/sidetree/spec/v1.0.0/#operation-verification
    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<Self::PartiallyVerifiedForm, PartialVerificationError>;
}

impl SidetreeOperation for Operation {
    type PartiallyVerifiedForm = PartiallyVerifiedOperation;

    fn partial_verify<S: Sidetree>(
        self,
    ) -> Result<Self::PartiallyVerifiedForm, PartialVerificationError> {
        match self {
            Operation::Create(op) => op
                .partial_verify::<S>()
                .map(PartiallyVerifiedOperation::Create),
            Operation::Update(op) => op
                .partial_verify::<S>()
                .map(PartiallyVerifiedOperation::Update),
            Operation::Recover(op) => op
                .partial_verify::<S>()
                .map(PartiallyVerifiedOperation::Recover),
            Operation::Deactivate(op) => op
                .partial_verify::<S>()
                .map(PartiallyVerifiedOperation::Deactivate),
        }
    }
}

impl PartiallyVerifiedOperation {
    pub fn update_commitment(&self) -> Option<&str> {
        match self {
            PartiallyVerifiedOperation::Create(create) => {
                Some(&create.hashed_delta.update_commitment)
            }
            PartiallyVerifiedOperation::Update(update) => {
                Some(&update.signed_delta.update_commitment)
            }
            PartiallyVerifiedOperation::Recover(recover) => {
                Some(&recover.signed_delta.update_commitment)
            }
            PartiallyVerifiedOperation::Deactivate(_) => None,
        }
    }

    pub fn recovery_commitment(&self) -> Option<&str> {
        match self {
            PartiallyVerifiedOperation::Create(create) => Some(&create.recovery_commitment),
            PartiallyVerifiedOperation::Update(_) => None,
            PartiallyVerifiedOperation::Recover(recover) => {
                Some(&recover.signed_recovery_commitment)
            }
            PartiallyVerifiedOperation::Deactivate(_) => None,
        }
    }

    pub fn follows<S: Sidetree>(
        &self,
        previous: &PartiallyVerifiedOperation,
    ) -> Result<(), FollowsError> {
        match self {
            PartiallyVerifiedOperation::Create(_) => Err(FollowsError::CreateCannotFollow),
            PartiallyVerifiedOperation::Update(update) => {
                let update_commitment = previous
                    .update_commitment()
                    .ok_or(FollowsError::MissingUpdateCommitment)?;
                ensure_reveal_commitment::<S>(
                    update_commitment,
                    &update.reveal_value,
                    &update.signed_update_key,
                )
            }
            PartiallyVerifiedOperation::Recover(recover) => {
                let recovery_commitment = previous
                    .recovery_commitment()
                    .ok_or(FollowsError::MissingRecoveryCommitment)?;
                ensure_reveal_commitment::<S>(
                    recovery_commitment,
                    &recover.reveal_value,
                    &recover.signed_recovery_key,
                )
            }
            PartiallyVerifiedOperation::Deactivate(deactivate) => {
                if let PartiallyVerifiedOperation::Create(create) = previous {
                    return Err(FollowsError::DIDSuffixMismatch {
                        expected: create.did_suffix.clone(),
                        actual: deactivate.signed_did_suffix.clone(),
                    });
                } else {
                    // Note: Recover operations do not sign over the DID suffix. If the deactivate
                    // operation follows a recover operation rather than a create operation, the
                    // DID Suffix must be verified by the caller.
                }
                let recovery_commitment = previous
                    .recovery_commitment()
                    .ok_or(FollowsError::MissingRecoveryCommitment)?;
                ensure_reveal_commitment::<S>(
                    recovery_commitment,
                    &deactivate.reveal_value,
                    &deactivate.signed_recovery_key,
                )
            }
        }
    }
}

fn ensure_reveal_commitment<S: Sidetree>(
    recovery_commitment: &str,
    reveal_value: &str,
    pk: &PublicKeyJwk,
) -> Result<(), FollowsError> {
    let canonicalized_public_key = json_canonicalization_scheme(&pk).unwrap();
    let commitment_value = canonicalized_public_key.as_bytes();
    let computed_reveal_value = S::reveal_value(commitment_value);
    if computed_reveal_value != reveal_value {
        return Err(FollowsError::RevealValueMismatch);
    }
    let computed_commitment = S::commitment_scheme(pk);
    if computed_commitment != recovery_commitment {
        return Err(FollowsError::CommitmentMismatch);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FollowsError {
    #[error("create cannot follow")]
    CreateCannotFollow,

    #[error("missing update commitment")]
    MissingUpdateCommitment,

    #[error("missing recovery commitment")]
    MissingRecoveryCommitment,

    #[error("DID suffix mismatch (expected {expected:?}, found {actual:?})")]
    DIDSuffixMismatch {
        expected: DIDSuffix,
        actual: DIDSuffix,
    },

    #[error("reveal value mismatch")]
    RevealValueMismatch,

    #[error("commitment mismatch")]
    CommitmentMismatch,
}

/// An error resulting from [jws_decode_verify_inner]
#[derive(thiserror::Error, Debug)]
pub enum JWSDecodeVerifyError {
    /// Unable to split JWS
    #[error("Unable to split JWS")]
    SplitJWS(#[source] ssi_jws::Error),
    /// Unable to decode JWS parts
    #[error("Unable to decode JWS parts")]
    DecodeJWSParts(#[source] ssi_jws::Error),
    /// Deserialize JWS payload
    #[error("Deserialize JWS payload")]
    DeserializeJWSPayload(#[source] serde_json::Error),
    /// Unable to convert PublicKeyJwk to JWK
    #[error("Unable to convert PublicKeyJwk to JWK")]
    JWKFromPublicKeyJwk(#[source] JWKFromPublicKeyJwkError),
    /// Unable to verify JWS
    #[error("Unable to verify JWS")]
    VerifyJWS(#[source] ssi_jws::Error),
}

/// Decode and verify JWS with public key inside payload
///
/// Similar to [ssi_jwt::decode_verify] or [ssi_jws::decode_verify], but for when the payload (claims) must be parsed to
/// determine the public key.
///
/// This function decodes and verifies a JWS/JWT, where the public key is expected to be found
/// within the payload (claims). Before verification, the deserialized claims object is passed to
/// the provided `get_key` function. The public key returned from the `get_key` function is then
/// used to verify the signature. The verified claims and header object are returned on successful
/// verification, along with the public key that they were verified against (as returned by the
/// `get_key` function).
///
/// The `get_key` function uses [PublicKeyJwk], for the convenience of this crate, but this
/// function converts it to [ssi_jwk::JWK] internally.
pub fn jws_decode_verify_inner<Claims: DeserializeOwned>(
    jwt: &str,
    get_key: impl FnOnce(&Claims) -> &PublicKeyJwk,
) -> Result<(ssi_jws::Header, Claims), JWSDecodeVerifyError> {
    use ssi_jws::{decode_jws_parts, split_jws, verify_bytes, DecodedJws};
    let (header_b64, payload_enc, signature_b64) =
        split_jws(jwt).map_err(JWSDecodeVerifyError::SplitJWS)?;
    let DecodedJws {
        signing_bytes:
            DecodedSigningBytes {
                bytes: signing_bytes,
                header,
                payload,
            },
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)
        .map_err(JWSDecodeVerifyError::DecodeJWSParts)?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(JWSDecodeVerifyError::DeserializeJWSPayload)?;
    let pk = get_key(&claims);
    let pk = JWK::try_from(pk.clone()).map_err(JWSDecodeVerifyError::JWKFromPublicKeyJwk)?;
    verify_bytes(header.algorithm, &signing_bytes, &pk, &signature)
        .map_err(JWSDecodeVerifyError::VerifyJWS)?;
    Ok((header, claims))
}
