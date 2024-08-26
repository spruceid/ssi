use core::fmt;
use std::borrow::Cow;

use base64::Engine;
use json_patch::Patch;
use serde::{Deserialize, Serialize};
use ssi_dids_core::{
    document::{service::Endpoint as ServiceEndpoint, Service},
    registration::{DIDDocumentOperation, DIDDocumentOperationKind, DIDTransactionCreationError},
};
use ssi_jwk::{Base64urlUInt, JWK};
use ssi_verification_methods::ProofPurpose;

mod client;
mod did;
mod operation;
mod resolver;

pub use client::*;
pub use did::*;
pub use operation::*;
pub use resolver::*;

const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];

/// Verification method type for Create operation
///
/// This is used when converting JWK to [verification method map][vmm] for the Create operation.
///
/// Reference: [Sidetree §12.1.1 `add-public-keys`][apk] Step 3.2
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
/// [vmm]: https://www.w3.org/TR/did-core/#verification-methods
pub const VERIFICATION_METHOD_TYPE: &str = "JsonWebSignature2020";

#[derive(Debug, thiserror::Error)]
#[error("key generation failed")]
pub struct KeyGenerationFailed;

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("same update and recovery keys")]
    SameUpdateAndRecoveryKeys,

    #[error(transparent)]
    KeyGenerationFailed(#[from] KeyGenerationFailed),

    #[error("invalid update key")]
    InvalidUpdateKey,

    #[error("invalid recovery key")]
    InvalidRecoveryKey,
}

impl From<CreateError> for DIDTransactionCreationError {
    fn from(value: CreateError) -> Self {
        match value {
            CreateError::SameUpdateAndRecoveryKeys => {
                DIDTransactionCreationError::SameUpdateAndRecoveryKeys
            }
            CreateError::KeyGenerationFailed(_) => DIDTransactionCreationError::KeyGenerationFailed,
            CreateError::InvalidUpdateKey => DIDTransactionCreationError::InvalidUpdateKey,
            CreateError::InvalidRecoveryKey => DIDTransactionCreationError::InvalidRecoveryKey,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("invalid update key")]
    InvalidUpdateKey,

    #[error("update key unchanged")]
    UpdateKeyUnchanged,

    #[error("signature failed")]
    SignatureFailed,
}

impl From<UpdateError> for DIDTransactionCreationError {
    fn from(value: UpdateError) -> Self {
        match value {
            UpdateError::InvalidUpdateKey => Self::InvalidUpdateKey,
            UpdateError::UpdateKeyUnchanged => Self::UpdateKeyUnchanged,
            UpdateError::SignatureFailed => Self::SignatureFailed,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeactivateError {
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    #[error("signature failed")]
    SignatureFailed,
}

impl From<DeactivateError> for DIDTransactionCreationError {
    fn from(value: DeactivateError) -> Self {
        match value {
            DeactivateError::InvalidRecoveryKey => Self::InvalidRecoveryKey,
            DeactivateError::SignatureFailed => Self::SignatureFailed,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    #[error("recovery key unchanged")]
    RecoveryKeyUnchanged,

    #[error("signature failed")]
    SignatureFailed,

    #[error(transparent)]
    KeyGenerationFailed(#[from] KeyGenerationFailed),
}

impl From<RecoverError> for DIDTransactionCreationError {
    fn from(value: RecoverError) -> Self {
        match value {
            RecoverError::InvalidRecoveryKey => Self::InvalidRecoveryKey,
            RecoverError::RecoveryKeyUnchanged => Self::RecoveryKeyUnchanged,
            RecoverError::SignatureFailed => Self::SignatureFailed,
            RecoverError::KeyGenerationFailed(_) => Self::KeyGenerationFailed,
        }
    }
}

/// Parameters for a Sidetree client implementation
///
/// This trait consistest of the subset of parameters defined in [Sidetree §5. Default Parameters][default-params] that are needed to implemented a Sidetree client, that is a client to the [Sidetree REST API][sidetree-rest].
///
/// [default-params]: https://identity.foundation/sidetree/spec/v1.0.0/#default-parameters
/// [sidetree-rest]: https://identity.foundation/sidetree/api/
pub trait Sidetree {
    /// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
    ///
    /// This should be implemented using [hash_algorithm].
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
    /// prefix and hash.
    ///
    /// This function must correspond with [hash_algorithm]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol(data: &[u8]) -> Vec<u8> {
        let (prefix, hash) = Self::hash_protocol_algorithm(data);
        [prefix, hash].concat()
    }

    /// [`HASH_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-algorithm)
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the hash, discarding the
    /// prefix.
    ///
    /// This function must correspond with [hash_protocol]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_algorithm(data: &[u8]) -> Vec<u8> {
        let (_prefix, hash) = Self::hash_protocol_algorithm(data);
        hash
    }

    /// Combination of [hash_protocol] and [hash_algorithm]
    ///
    /// Returns multihash prefix and hash.
    ///
    /// Default implementation: SHA-256 (`sha2-256`)
    ///
    /// [hash_protocol] and [hash_algorithm] must correspond, and their default implementations
    /// call this function ([hash_protocol_algorithm]). Implementers are therefore encouraged to
    /// overwrite this function ([hash_protocol_algorithm]) rather than those ([hash_protocol] and
    /// [hash_algorithm]).
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol_algorithm(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        (
            [MULTIHASH_SHA2_256_PREFIX, MULTIHASH_SHA2_256_SIZE].concat(),
            hash,
        )
    }

    /// [`DATA_ENCODING_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#data-encoding-scheme)
    fn data_encoding_scheme(data: &[u8]) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    /// Generate a new keypair ([KEY_ALGORITHM][ka])
    ///
    /// [ka]: https://identity.foundation/sidetree/spec/v1.0.0/#key-algorithm
    fn generate_key() -> JWK;

    /// Ensure that a keypair is valid for this Sidetree DID Method
    ///
    /// Check that the key uses this Sidetree DID method's [KEY_ALGORITHM][ka].
    ///
    /// [ka]: https://identity.foundation/sidetree/spec/v1.0.0/#key-algorithm
    fn validate_key(key: &JWK) -> bool;

    /// [`SIGNATURE_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#sig-algorithm) (JWS alg)
    const SIGNATURE_ALGORITHM: ssi_jwk::Algorithm;

    /// [`REVEAL_VALUE`](https://identity.foundation/sidetree/spec/v1.0.0/#reveal-value)
    fn reveal_value(commitment_value: &[u8]) -> String {
        // The spec implies that REVEAL_VALUE uses HASH_PROTOCOL, in §6.2.1:
        //   "Use the implementation’s HASH_PROTOCOL to hash the canonicalized public key to generate the REVEAL_VALUE"
        //   https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
        let hash = Self::hash_protocol(commitment_value);
        Self::data_encoding_scheme(&hash)
    }

    /// [`MAX_OPERATION_HASH_LENGTH`](https://identity.foundation/sidetree/spec/v1.0.0/#max-operation-hash-length)
    const MAX_OPERATION_HASH_LENGTH: usize = 100;

    /// [`NONCE_SIZE`](https://identity.foundation/sidetree/spec/v1.0.0/#nonce-size)
    const NONCE_SIZE: usize = 16;

    /// Method name for Sidetree-based DID
    ///
    /// Mentioned in [Sidetree §9. DID URI Composition](https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition)
    const METHOD: &'static str;

    /// Network instance
    ///
    /// Additional segment after the method-id (METHOD), as a prefix for the method-specific-id
    /// (DID Suffix), identifiying a network instance. e.g. "testnet"
    ///
    /// Mentioned in [Note 1](https://identity.foundation/sidetree/spec/v1.0.0/#note-1)
    const NETWORK: Option<&'static str> = None;

    /// Maximum length of `controller` property
    ///
    /// Reference: [Sidetree §12.1.1 `add-public-keys`](https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys)
    const MAX_CONTROLLER_LENGTH: Option<usize> = None;

    /// Maximum length of `publicKeyMultibase` property
    ///
    /// Reference: [Sidetree §12.1.1 `add-public-keys`](https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys)
    const MAX_PKMB_LENGTH: Option<usize> = None;

    /// Hash and encode data
    ///
    /// [Sidetree §6.1 Hashing Process](https://identity.foundation/sidetree/spec/#hashing-process)
    fn hash(data: &[u8]) -> String {
        let hash = Self::hash_protocol(data);
        /*
        ensure!(
            hash.len() <= Self::MAX_OPERATION_HASH_LENGTH,
            "Hash is too long"
        );
        */
        Self::data_encoding_scheme(&hash)
    }

    /// [Public Key Commitment Scheme (Sidetree §6.2.1)][pkcs]
    ///
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn commitment_scheme(pkjwk: &PublicKeyJwk) -> String {
        let canonicalized_public_key = json_canonicalization_scheme(&pkjwk).unwrap();
        // Note: hash_algorithm called here instead of reveal_value, since the underlying hash is
        // used, not the encoded/prefixed one.
        let reveal_value = Self::hash_algorithm(canonicalized_public_key.as_bytes());
        Self::hash(&reveal_value)
    }

    /// Create a Sidetree-based DID using existing keys
    ///
    /// This function creates a Sidetree-based DID using existing public keys for
    /// the update key and recovery key and respective
    /// [commitments][].
    ///
    /// Sidetree specifies in ([§11.1 Create][create]) that creating a Sidetree DID involves
    /// generating a Update keypair and Recovery keypair. That is implemented in [Self::create].
    ///
    /// **Note**: The Sidetree specification ([§6.2.1 Public Key Commitment
    /// Scheme][pkcs]) recommends not reusing public keys across different commitment invocations, and
    /// requires not using public key JWK payloads across commitment invocations.
    ///
    /// [commitments]: https://identity.foundation/sidetree/spec/v1.0.0/#commitment
    /// [create]: https://identity.foundation/sidetree/spec/v1.0.0/#create
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn create_existing(
        update_pk: &PublicKeyJwk,
        recovery_pk: &PublicKeyJwk,
        patches: Vec<DIDStatePatch>,
    ) -> Result<Operation, CreateError> {
        if update_pk == recovery_pk {
            return Err(CreateError::SameUpdateAndRecoveryKeys);
        }

        let update_commitment = Self::commitment_scheme(update_pk);

        let create_operation_delta_object = Delta {
            patches,
            update_commitment,
        };
        let delta_string = json_canonicalization_scheme(&create_operation_delta_object).unwrap();
        let delta_hash = Self::hash(delta_string.as_bytes());

        let recovery_commitment = Self::commitment_scheme(recovery_pk);

        let create_operation_suffix_data_object = SuffixData {
            r#type: None,
            delta_hash,
            recovery_commitment,
            anchor_origin: None,
        };

        let create_operation = CreateOperation {
            suffix_data: create_operation_suffix_data_object,
            delta: create_operation_delta_object,
        };

        Ok(Operation::Create(create_operation))
    }

    /// Create a Sidetree-based DID
    ///
    /// Generate keypairs and construct a Create Operation according to [Sidetree §11.1
    /// Create][create]. Returns the private keys and the create operation.
    ///
    /// [create]: https://identity.foundation/sidetree/spec/v1.0.0/#create
    fn create(patches: Vec<DIDStatePatch>) -> Result<(Operation, JWK, JWK), CreateError> {
        let update_keypair = Self::generate_key();
        let recovery_keypair = Self::generate_key();
        let update_pk = PublicKeyJwk::try_from(update_keypair.to_public())
            .map_err(|_| CreateError::InvalidUpdateKey)?;
        let recovery_pk = PublicKeyJwk::try_from(recovery_keypair.to_public())
            .map_err(|_| CreateError::InvalidRecoveryKey)?;
        let create_op = Self::create_existing(&update_pk, &recovery_pk, patches)?;
        Ok((create_op, update_keypair, recovery_keypair))
    }

    /// Create a Sidetree-based DID
    ///
    /// Construct a DID Update Operation according to [Sidetree §11.2
    /// Update][update]. Returns the update operation.
    ///
    /// Unlike [Self::create] and [Self::recover], this does not generate keys, since the specification does not
    /// call for that here. Instead, the caller must generate a new update keypair, and pass
    /// its public key in the `new_update_pk` argument.
    ///
    /// Using a `update_key` with a [JWK Nonce][jwkn] is not yet supported.
    ///
    /// [update]: https://identity.foundation/sidetree/spec/v1.0.0/#update
    /// [jwkn]: https://identity.foundation/sidetree/spec/#jwk-nonce
    fn update(
        did_suffix: DIDSuffix,
        update_key: &JWK,
        new_update_pk: &PublicKeyJwk,
        patches: Vec<DIDStatePatch>,
    ) -> Result<UpdateOperation, UpdateError> {
        let update_pk = PublicKeyJwk::try_from(update_key.to_public())
            .map_err(|_| UpdateError::InvalidUpdateKey)?;
        let canonicalized_update_pk = json_canonicalization_scheme(&update_pk).unwrap();
        let update_reveal_value = Self::reveal_value(canonicalized_update_pk.as_bytes());

        if new_update_pk == &update_pk {
            return Err(UpdateError::UpdateKeyUnchanged);
        }

        let new_update_commitment = Self::commitment_scheme(new_update_pk);

        let update_operation_delta_object = Delta {
            patches,
            update_commitment: new_update_commitment,
        };

        let delta_string = json_canonicalization_scheme(&update_operation_delta_object).unwrap();
        let delta_hash = Self::hash(delta_string.as_bytes());

        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = UpdateClaims {
            update_key: update_pk,
            delta_hash,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, update_key)
            .map_err(|_| UpdateError::SignatureFailed)?;
        let update_op = UpdateOperation {
            did_suffix,
            reveal_value: update_reveal_value,
            delta: update_operation_delta_object,
            signed_data,
        };

        Ok(update_op)
    }

    /// Recover a Sidetree-based DID using existing keys
    ///
    /// Like [Self::recover] but does not generate or handle the new update key pair and recovery
    /// key pair; instead, their public keys must be provided by the caller in the `new_update_pk`
    /// and `new_recovery_pk` arguments.
    ///
    /// Returns the constructed DID Recover operation.
    fn recover_existing(
        did_suffix: DIDSuffix,
        recovery_key: &JWK,
        new_update_pk: &PublicKeyJwk,
        new_recovery_pk: &PublicKeyJwk,
        patches: Vec<DIDStatePatch>,
    ) -> Result<Operation, RecoverError> {
        let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public())
            .map_err(|_| RecoverError::InvalidRecoveryKey)?;

        if new_recovery_pk == &recovery_pk {
            return Err(RecoverError::RecoveryKeyUnchanged);
        }

        let canonicalized_recovery_pk = json_canonicalization_scheme(&recovery_pk).unwrap();
        let recover_reveal_value = Self::reveal_value(canonicalized_recovery_pk.as_bytes());
        let new_update_commitment = Self::commitment_scheme(new_update_pk);
        let new_recovery_commitment = Self::commitment_scheme(new_recovery_pk);

        let recover_operation_delta_object = Delta {
            patches,
            update_commitment: new_update_commitment,
        };

        let delta_string = json_canonicalization_scheme(&recover_operation_delta_object).unwrap();
        let delta_hash = Self::hash(delta_string.as_bytes());

        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = RecoveryClaims {
            recovery_commitment: new_recovery_commitment,
            recovery_key: recovery_pk,
            delta_hash,
            anchor_origin: None,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, recovery_key)
            .map_err(|_| RecoverError::SignatureFailed)?;
        let recover_op = RecoverOperation {
            did_suffix,
            reveal_value: recover_reveal_value,
            delta: recover_operation_delta_object,
            signed_data,
        };
        Ok(Operation::Recover(recover_op))
    }

    /// Recover a Sidetree-based DID
    ///
    /// Generate keypairs and construct a Recover Operation according to [Sidetree §11.3
    /// Recover][recover]. Returns the recover operation.
    ///
    /// [recover]: https://identity.foundation/sidetree/spec/v1.0.0/#recover
    fn recover(
        did_suffix: DIDSuffix,
        recovery_key: &JWK,
        patches: Vec<DIDStatePatch>,
    ) -> Result<(Operation, JWK, JWK), RecoverError> {
        let new_update_keypair = Self::generate_key();
        let new_update_pk = PublicKeyJwk::try_from(new_update_keypair.to_public()).unwrap();

        let new_recovery_keypair = Self::generate_key();
        let new_recovery_pk = PublicKeyJwk::try_from(new_recovery_keypair.to_public()).unwrap();

        let recover_op = Self::recover_existing(
            did_suffix,
            recovery_key,
            &new_update_pk,
            &new_recovery_pk,
            patches,
        )?;

        Ok((recover_op, new_update_keypair, new_recovery_keypair))
    }

    /// Deactivate a Sidetree-based DID
    ///
    /// Construct a Deactivate Operation according to [Sidetree §11.4
    /// Deactivate][deactivate]. Returns the deactivate operation.
    ///
    /// [deactivate]: https://identity.foundation/sidetree/spec/v1.0.0/#deactivate
    fn deactivate(
        did_suffix: DIDSuffix,
        recovery_key: JWK,
    ) -> Result<DeactivateOperation, DeactivateError> {
        let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public())
            .map_err(|_| DeactivateError::InvalidRecoveryKey)?;
        let canonicalized_recovery_pk = json_canonicalization_scheme(&recovery_pk).unwrap();
        let recover_reveal_value = Self::reveal_value(canonicalized_recovery_pk.as_bytes());
        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = DeactivateClaims {
            did_suffix: did_suffix.clone(),
            recovery_key: recovery_pk,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, &recovery_key)
            .map_err(|_| DeactivateError::SignatureFailed)?;
        let recover_op = DeactivateOperation {
            did_suffix,
            reveal_value: recover_reveal_value,
            signed_data,
        };
        Ok(recover_op)
    }

    /// Serialize and hash [Suffix Data][SuffixData], to generate a [Short-Form Sidetree
    /// DID][SidetreeDID::Short] ([`DIDSuffix`]).
    ///
    /// Reference: <https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition>
    fn serialize_suffix_data(suffix_data: &SuffixData) -> DIDSuffix {
        let string = json_canonicalization_scheme(suffix_data).unwrap();
        let hash = Self::hash(string.as_bytes());
        DIDSuffix(hash)
    }

    /// Check that a DID Suffix looks valid
    fn validate_did_suffix(suffix: &DIDSuffix) -> Result<(), InvalidSidetreeDIDSuffix> {
        let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(&suffix.0)
            .map_err(|_| InvalidSidetreeDIDSuffix::Base64)?;

        if bytes.len() != 34 {
            return Err(InvalidSidetreeDIDSuffix::Length(bytes.len()));
        }

        if &bytes[0..1] != MULTIHASH_SHA2_256_PREFIX || &bytes[1..2] != MULTIHASH_SHA2_256_SIZE {
            return Err(InvalidSidetreeDIDSuffix::Prefix);
        }

        Ok(())
    }
}

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
fn json_canonicalization_scheme<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidSidetreeDIDSuffix {
    #[error("invalid base64")]
    Base64,

    #[error("unexpected DID suffix length ({0})")]
    Length(usize),

    #[error("unexpected DID suffix prefix")]
    Prefix,
}

/// Public key as JWK or Multibase
///
/// Property of a public key / verification method containing public key data,
/// as part of a [PublicKeyEntry][].
///
/// per [Sidetree §12.1.1 `add-public-keys`: Step 4][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PublicKey {
    /// [`publicKeyJwk`](https://www.w3.org/TR/did-core/#dfn-publickeyjwk) as defined in DID Core.
    ///
    /// JSON Web Key (JWK) is specified in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
    PublicKeyJwk(PublicKeyJwk),

    /// [`publicKeyMultibase`](https://www.w3.org/TR/did-core/#dfn-publickeymultibase) as defined in DID Core.
    ///
    /// Maximum length may be set in [Sidetree::MAX_PKMB_LENGTH].
    PublicKeyMultibase(String),
}

/// Public Key Entry
///
/// Used by the [`add-public-keys`](DIDStatePatch::AddPublicKeys) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree §12.1.1 `add-public-keys`][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64url
    pub id: String,

    /// Verification method type
    pub r#type: String,

    /// Verification method controller (DID)
    ///
    /// Maximum length may be set in [Sidetree::MAX_CONTROLLER_LENGTH].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    /// `publicKeyJwk` or `publicKeyMultibase` property
    #[serde(flatten)]
    pub public_key: PublicKey,

    /// Verification relationships
    ///
    /// Defined in [DID Core](https://www.w3.org/TR/did-core/#verification-relationships).
    ///
    /// Corresponds to [`proofPurpose`](https://www.w3.org/TR/did-core/#verification-relationships) in VC Data Model.
    pub purposes: Vec<ProofPurpose>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid public key entry")]
pub struct InvalidPublicKeyEntry(pub JWK);

impl TryFrom<JWK> for PublicKeyEntry {
    type Error = InvalidPublicKeyEntry;

    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let Ok(id) = jwk.thumbprint() else {
            return Err(InvalidPublicKeyEntry(jwk));
        };

        let Ok(pkjwk) = PublicKeyJwk::try_from(jwk.to_public()) else {
            return Err(InvalidPublicKeyEntry(jwk));
        };

        let public_key = PublicKey::PublicKeyJwk(pkjwk);
        Ok(PublicKeyEntry {
            id,
            r#type: VERIFICATION_METHOD_TYPE.to_owned(),
            controller: None,
            public_key,
            purposes: vec![
                ProofPurpose::Assertion,
                ProofPurpose::Authentication,
                ProofPurpose::KeyAgreement,
                ProofPurpose::CapabilityInvocation,
                ProofPurpose::CapabilityDelegation,
            ],
        })
    }
}

/// Service Endpoint Entry
///
/// Used by the [`add-services`](DIDStatePatch::AddServices) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree §12.1.3 `add-services`][as].
///
/// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpointEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64Url
    pub id: String,

    /// Service type
    ///
    /// Maximum length: 30 in Base64Url
    pub r#type: String,

    /// Service endpoint URL or object
    pub service_endpoint: ServiceEndpoint,
}

/// DID PKI metadata state
///
/// Used by the [`replace`](DIDStatePatch::Replace) DID state patch.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentState {
    /// Public key entries

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKeyEntry>>,

    /// Services
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceEndpointEntry>>,
}

/// [DID State Patch][dsp] using a [Sidetree Standard Patch action][spa]
///
/// [dsp]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
/// [spa]: https://identity.foundation/sidetree/spec/v1.0.0/#standard-patch-actions
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all = "kebab-case")]
pub enum DIDStatePatch {
    /// [`add-public-keys`][apk] Patch Action
    ///
    /// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
    AddPublicKeys {
        /// Keys to add or over overwrite
        #[serde(rename = "publicKeys")]
        public_keys: Vec<PublicKeyEntry>,
    },

    /// [`remove-public-keys`][rpk] Patch Action
    ///
    /// [rpk]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-public-keys
    RemovePublicKeys {
        /// IDs of keys to remove
        ids: Vec<String>,
    },

    /// [`add-services`][as] Patch Action
    ///
    /// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
    AddServices {
        /// Service entries to add
        services: Vec<ServiceEndpointEntry>,
    },

    /// [`remove-services`][rs] Patch Action
    ///
    /// [rs]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-services
    RemoveServices {
        /// IDs of service endpoints to remove
        ids: Vec<String>,
    },

    /// [`replace`][r] Patch Action
    ///
    /// [r]: https://identity.foundation/sidetree/spec/v1.0.0/#replace
    Replace {
        /// Reset DID state
        document: DocumentState,
    },

    /// [`ietf-json-patch`][ijp] Patch Action
    ///
    /// [ijp]: https://identity.foundation/sidetree/spec/v1.0.0/#ietf-json-patch
    ///
    IetfJsonPatch {
        /// JSON Patches according to [RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902).
        patches: Patch,
    },
}

/// Create/Update/Recover Delta Object
///
/// ### References
/// - [Sidetree §11.1 Create - Create Operation Delta Object][codo]
/// - [Sidetree §11.2 Update - Update Operation Delta Object][uodo]
/// - [Sidetree §11.3 Recover - Recover Operation Delta Object][rodo]
///
/// [codo]: https://identity.foundation/sidetree/spec/v1.0.0/#create-delta-object
/// [uodo]: https://identity.foundation/sidetree/spec/v1.0.0/#update-delta-object
/// [rodo]: https://identity.foundation/sidetree/spec/v1.0.0/#recover-delta-object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    /// DID state patches to apply.
    pub patches: Vec<DIDStatePatch>,

    /// Update commitment generated as part of a Sidetree Create or Update operation.
    pub update_commitment: String,
}

/// Public Key JWK (JSON Web Key)
///
/// Wraps [ssi_jwk::JWK], while allowing a `nonce` property, and disallowing private key
/// properties ("d").
///
/// Sidetree may allow a `nonce` property in public key JWKs ([§6.2.2 JWK Nonce][jwkn]).
///
/// [jwkn]: https://identity.foundation/sidetree/spec/#jwk-nonce
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Base64urlUInt>,
    #[serde(flatten)]
    jwk: serde_json::Value,
}

/// Error resulting from [converting JWK to PublicKeyJwk][PublicKeyJwk::try_from]
#[derive(thiserror::Error, Debug)]
pub enum PublicKeyJwkFromJWKError {
    /// Public Key JWK must not contain private key parameters (e.g. "d")
    #[error("Public Key JWK must not contain private key parameters")]
    PrivateKeyParameters,
}

/// Error resulting from attempting to convert [PublicKeyJwk] to JWK
#[derive(thiserror::Error, Debug)]
pub enum JWKFromPublicKeyJwkError {
    /// Unable to convert [`serde_json::Value`] to JWK
    #[error("Unable to convert Value to JWK")]
    FromValue(#[from] serde_json::Error),
}

impl TryFrom<JWK> for PublicKeyJwk {
    type Error = PublicKeyJwkFromJWKError;
    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let jwk_value = serde_json::to_value(jwk).unwrap();
        if jwk_value.get("d").is_some() {
            return Err(PublicKeyJwkFromJWKError::PrivateKeyParameters);
        };
        Ok(Self {
            jwk: jwk_value,
            nonce: None,
        })
    }
}

/// Convert [PublicKeyJwk] to [JWK].
///
/// Note: `nonce` property is dropped.
impl TryFrom<PublicKeyJwk> for JWK {
    type Error = JWKFromPublicKeyJwkError;
    fn try_from(pkjwk: PublicKeyJwk) -> Result<Self, Self::Error> {
        let jwk = serde_json::from_value(pkjwk.jwk).map_err(JWKFromPublicKeyJwkError::FromValue)?;
        Ok(jwk)
    }
}

fn b64len(s: &str) -> usize {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(s).len()
}

impl DIDStatePatch {
    /// Convert a [DID Document Operation][ddo] and DID to a Sidetree [DID State Patch][dsp].
    ///
    /// [ddp]: https://identity.foundation/did-registration/#diddocumentoperation
    /// [dsp]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
    fn try_from_with_did<S: Sidetree>(
        did_doc_op: DIDDocumentOperation,
        did: &SidetreeDID<S>,
    ) -> Result<Self, DIDTransactionCreationError> {
        match did_doc_op {
            DIDDocumentOperation::SetDidDocument(_doc) => {
                Err(DIDTransactionCreationError::UnimplementedDocumentOperation(
                    DIDDocumentOperationKind::SetDidDocument,
                ))
            }
            DIDDocumentOperation::AddToDidDocument(_props) => {
                Err(DIDTransactionCreationError::UnimplementedDocumentOperation(
                    DIDDocumentOperationKind::AddToDidDocument,
                ))
            }
            DIDDocumentOperation::RemoveFromDidDocument(_props) => {
                Err(DIDTransactionCreationError::UnimplementedDocumentOperation(
                    DIDDocumentOperationKind::RemoveFromDidDocument,
                ))
            }
            DIDDocumentOperation::SetVerificationMethod { vmm, purposes } => {
                let sub_id = did_url_to_id(&vmm.id, did)?;
                let mut value = serde_json::to_value(vmm).unwrap();
                value["id"] = serde_json::Value::String(sub_id);
                value["purposes"] = serde_json::to_value(purposes).unwrap();
                let entry: PublicKeyEntry = serde_json::from_value(value)
                    .map_err(|_| DIDTransactionCreationError::InvalidVerificationMethod)?;
                // TODO: allow omitted controller property
                Ok(DIDStatePatch::AddPublicKeys {
                    public_keys: vec![entry],
                })
            }
            DIDDocumentOperation::SetService(service) => {
                let Service {
                    id,
                    type_,
                    service_endpoint,
                    property_set,
                } = service;

                if !property_set.is_empty() {
                    return Err(DIDTransactionCreationError::UnsupportedServiceProperty);
                }

                let service_endpoint = match service_endpoint {
                    None => return Err(DIDTransactionCreationError::MissingServiceEndpoint),
                    Some(values) => match values.into_single() {
                        Some(value) => value,
                        None => return Err(DIDTransactionCreationError::AmbiguousServiceEndpoint),
                    },
                };

                let sub_id = did_url_to_id(&id, did)?;
                let service_type = match type_.into_single() {
                    Some(type_) => type_,
                    None => return Err(DIDTransactionCreationError::AmbiguousServiceType),
                };

                if b64len(&service_type) > 30 {
                    return Err(DIDTransactionCreationError::UnsupportedService {
                        reason: Cow::Borrowed("Sidetree service type must contain no more than 30 Base64Url-encoded characters")
                    });
                }

                if b64len(&sub_id) > 50 {
                    return Err(DIDTransactionCreationError::UnsupportedService {
                        reason: Cow::Borrowed("Sidetree service id must contain no more than 50 Base64Url-encoded characters")
                    });
                }

                let entry = ServiceEndpointEntry {
                    id: sub_id,
                    r#type: service_type,
                    service_endpoint,
                };

                Ok(DIDStatePatch::AddServices {
                    services: vec![entry],
                })
            }
            DIDDocumentOperation::RemoveVerificationMethod(did_url) => {
                let id = did_url.to_string();
                Ok(DIDStatePatch::RemovePublicKeys { ids: vec![id] })
            }
            DIDDocumentOperation::RemoveService(did_url) => {
                let id = did_url.to_string();
                Ok(DIDStatePatch::RemoveServices { ids: vec![id] })
            }
        }
    }
}

/// Convert a DID URL to an object id given a DID
///
/// Object id is an id of a [ServiceEndpointEntry] or [PublicKeyEntry].
fn did_url_to_id<S: Sidetree>(
    did_url: &str,
    did: &SidetreeDID<S>,
) -> Result<String, DIDTransactionCreationError> {
    let did_string = did.to_string();
    let unprefixed = did_url
        .strip_prefix(&did_string)
        .ok_or(DIDTransactionCreationError::InvalidDIDURL)?;
    let fragment = unprefixed
        .strip_prefix('#')
        .ok_or(DIDTransactionCreationError::InvalidDIDURL)?;
    Ok(fragment.to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SidetreeAPIError {
    // List of error codes: https://github.com/decentralized-identity/sidetree/blob/v1.0.0/lib/core/versions/1.0/ErrorCode.ts
    pub code: String,
    pub message: Option<String>,
}

impl fmt::Display for SidetreeAPIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sidetree error {}", self.code)?;
        if let Some(ref message) = self.message {
            write!(f, ": {}", message)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::ion::is_secp256k1;

    use super::*;
    use serde_json::json;
    use ssi_jwk::Algorithm;

    struct Example;

    impl Sidetree for Example {
        fn generate_key() -> JWK {
            JWK::generate_secp256k1()
        }
        fn validate_key(key: &JWK) -> bool {
            is_secp256k1(key)
        }
        const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
        const METHOD: &'static str = "sidetree";
    }

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#did>
    static LONGFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
    static SHORTFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg";

    lazy_static::lazy_static! {

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#create-2>
        static ref CREATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "create",
          "suffixData": {
            "deltaHash": "EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg",
            "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA"
          },
          "delta": {
            "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA",
            "patches": [
              {
                "action": "replace",
                "document": {
                  "publicKeys": [
                    {
                      "id": "publicKeyModel1Id",
                      "type": "EcdsaSecp256k1VerificationKey2019",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "secp256k1",
                        "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                        "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                      },
                      "purposes": [
                        "authentication",
                        "keyAgreement"
                      ]
                    }
                  ],
                  "services": [
                    {
                      "id": "service1Id",
                      "type": "service1Type",
                      "serviceEndpoint": "http://www.service1.com"
                    }
                  ]
                }
              }
            ]
          }
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#update-2>
        static ref UPDATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "update",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiBkRSeixqX-PhOij6PIpuGfPld5Nif5MxcrgtGCw-t6LA",
          "delta": {
            "patches": [
              {
                "action": "add-public-keys",
                "publicKeys": [
                  {
                    "id": "additional-key",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "publicKeyJwk": {
                      "kty": "EC",
                      "crv": "secp256k1",
                      "x": "aN75CTjy3VCgGAJDNJHbcb55hO8CobEKzgCNrUeOwAY",
                      "y": "K9FhCEpa_jG09pB6qriXrgSvKzXm6xtxBvZzIoXXWm4"
                    },
                    "purposes": [
                      "authentication",
                      "assertionMethod",
                      "capabilityInvocation",
                      "capabilityDelegation",
                      "keyAgreement"
                    ]
                  }
                ]
              }
            ],
            "updateCommitment": "EiDOrcmPtfMHuwIWN6YoihdeIPxOKDHy3D6sdMXu_7CN0w"
          },
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4Ijoid2Z3UUNKM09ScVZkbkhYa1Q4UC1MZ19HdHhCRWhYM3R5OU5VbnduSHJtdyIsInkiOiJ1aWU4cUxfVnVBblJEZHVwaFp1eExPNnFUOWtQcDNLUkdFSVJsVHBXcmZVIn0sImRlbHRhSGFzaCI6IkVpQ3BqTjQ3ZjBNcTZ4RE5VS240aFNlZ01FcW9EU19ycFEyOVd5MVY3M1ZEYncifQ.RwZK1DG5zcr4EsrRImzStb0VX5j2ZqApXZnuoAkA3IoRdErUscNG8RuxNZ0FjlJtjMJ0a-kn-_MdtR0wwvWVgg"
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#recover-2>
        static ref RECOVER_OPERATION: Operation = serde_json::from_value(json!({
          "type": "recover",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ",
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkZWx0YUhhc2giOiJFaUNTem1ZSk0yWGpaWE00a1Q0bGpKcEVGTjVmVkM1QVNWZ3hSekVtMEF2OWp3IiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NBN1NHTE5lZGE1SW5sb3Fub2tVY0pGejZ2S1Q0SFM1ZGNLcm1ubEpocEEifQ.lxWnrg5jaeCAhYuz1fPhidKw6Z2cScNlEc6SWcs15DtJbrHZFxl5IezGJ3cWdOSS2DlzDl4M1ZF8dDE9kRwFeQ",
          "delta": {
            "patches": [
              {
                "action": "replace",
                "document": {
                  "publicKeys": [
                    {
                      "id": "newKey",
                      "type": "EcdsaSecp256k1VerificationKey2019",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "secp256k1",
                        "x": "JUWp0pAMGevNLhqq_Qmd48izuLYfO5XWpjSmy5btkjc",
                        "y": "QYaSu1NHYnxR4qfk-RkXb4NQnQf1X3XQCpDYuibvlNc"
                      },
                      "purposes": [
                        "authentication",
                        "assertionMethod",
                        "capabilityInvocation",
                        "capabilityDelegation",
                        "keyAgreement"
                      ]
                    }
                  ],
                  "services": [
                    {
                      "id": "serviceId123",
                      "type": "someType",
                      "serviceEndpoint": "https://www.url.com"
                    }
                  ]
                }
              }
            ],
            "updateCommitment": "EiD6_csybTfxELBoMgkE9O2BTCmhScG_RW_qaZQkIkJ_aQ"
          }
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#deactivate-2>
        static ref DEACTIVATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "deactivate",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiB-dib5oumdaDGH47TB17Qg1nHza036bTIGibQOKFUY2A",
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoiSk1ucF9KOW5BSGFkTGpJNmJfNVU3M1VwSEZqSEZTVHdtc1ZUUG9FTTVsMCIsInkiOiJ3c1QxLXN0UWJvSldPeEJyUnVINHQwVV9zX1lSQy14WXQyRkFEVUNHR2M4In19.ARTZrvupKdShOFNAJ4EWnsuaONKBgXUiwY5Ct10a9IXIp1uFsg0UyDnZGZtJT2v2bgtmYsQBmT6L9kKaaDcvUQ"
        })).unwrap();
    }

    #[test]
    fn test_did_parse_format() {
        let longform_did = SidetreeDID::<Example>::from_str(LONGFORM_DID).unwrap();
        let shortform_did = SidetreeDID::<Example>::from_str(SHORTFORM_DID).unwrap();
        assert_eq!(longform_did.to_string(), LONGFORM_DID);
        assert_eq!(shortform_did.to_string(), SHORTFORM_DID);
        assert!(LONGFORM_DID.starts_with(SHORTFORM_DID));
    }

    #[test]
    fn test_longform_did_construction() {
        let create_operation = match &*CREATE_OPERATION {
            Operation::Create(op) => op,
            _ => panic!("Expected Create Operation"),
        };
        let did: SidetreeDID<Example> = create_operation.to_sidetree_did();
        assert_eq!(did.to_string(), LONGFORM_DID);
    }

    #[test]
    fn test_update_verify_reveal() {
        let create_pvo = CREATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let update_pvo = UPDATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        update_pvo.follows::<Example>(&create_pvo).unwrap();
    }

    #[test]
    fn test_recover_verify_reveal() {
        let create_pvo = CREATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let recover_pvo = RECOVER_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        recover_pvo.follows::<Example>(&create_pvo).unwrap();
    }

    #[test]
    fn test_deactivate_verify_reveal() {
        let recover_pvo = RECOVER_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let deactivate_pvo = DEACTIVATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        deactivate_pvo.follows::<Example>(&recover_pvo).unwrap();
    }
}
