use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
use async_trait::async_trait;
use core::fmt::Debug;
use json_patch::Patch;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use ssi_core::one_or_many::OneOrMany;
use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, HTTPDIDResolver, ResolutionInputMetadata, ResolutionMetadata,
    ERROR_INVALID_DID,
};
use ssi_dids::{
    DIDCreate, DIDDeactivate, DIDDocumentOperation, DIDMethod, DIDMethodError,
    DIDMethodTransaction, DIDRecover, DIDUpdate, Document, Service, ServiceEndpoint,
    VerificationRelationship,
};
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use ssi_jws::Header;
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error as ThisError;

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

/// An error having to do with [Sidetree].
#[derive(ThisError, Debug)]
pub enum SidetreeError {
    /// Some functionality was not implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
    /// Error from [serde_jcs::to_string]
    #[error("Unable to execute JSON Canonicalization Scheme (JCS)")]
    JCS(#[from] serde_json::Error),
    /// A create operation following another operation is not valid.
    #[error("Create operation cannot follow another operation")]
    CreateCannotFollow,
    /// Update commitment is missing
    #[error("Missing update commitment")]
    MissingUpdateCommitment,
    /// Recovery commitment is missing
    #[error("Missing recovery commitment")]
    MissingRecoveryCommitment,
    /// DID Suffix did not match expected value.
    #[error("DID Suffix mismatch. Expected: '{expected}', but found '{actual}'")]
    DIDSuffixMismatch {
        expected: DIDSuffix,
        actual: DIDSuffix,
    },
    /// Some error occurred.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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
        base64::encode_config(data, base64::URL_SAFE_NO_PAD)
    }

    /// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
    fn json_canonicalization_scheme<T: Serialize + ?Sized>(
        value: &T,
    ) -> Result<String, SidetreeError> {
        serde_jcs::to_string(value).map_err(SidetreeError::JCS)
    }

    /// Generate a new keypair ([KEY_ALGORITHM][ka])
    ///
    /// [ka]: https://identity.foundation/sidetree/spec/v1.0.0/#key-algorithm
    fn generate_key() -> Result<JWK, SidetreeError>;

    /// Ensure that a keypair is valid for this Sidetree DID Method
    ///
    /// Check that the key uses this Sidetree DID method's [KEY_ALGORITHM][ka].
    ///
    /// [ka]: https://identity.foundation/sidetree/spec/v1.0.0/#key-algorithm
    fn validate_key(key: &JWK) -> Result<(), SidetreeError>;

    /// [`SIGNATURE_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#sig-algorithm) (JWS alg)
    const SIGNATURE_ALGORITHM: Algorithm;

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
    fn commitment_scheme(pkjwk: &PublicKeyJwk) -> AResult<String> {
        let canonicalized_public_key =
            Self::json_canonicalization_scheme(&pkjwk).context("Canonicalize JWK")?;
        // Note: hash_algorithm called here instead of reveal_value, since the underlying hash is
        // used, not the encoded/prefixed one.
        let reveal_value = Self::hash_algorithm(canonicalized_public_key.as_bytes());
        let commitment = Self::hash(&reveal_value);
        Ok(commitment)
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
    ) -> AResult<Operation> {
        ensure!(
            update_pk != recovery_pk,
            "Update and recovery public key JWK payload must be different."
        );

        let update_commitment =
            Self::commitment_scheme(update_pk).context("Generate update commitment")?;

        let create_operation_delta_object = Delta {
            patches,
            update_commitment,
        };
        let delta_string = Self::json_canonicalization_scheme(&create_operation_delta_object)
            .context("Canonicalize Create Operation Delta Object")?;
        let delta_hash = Self::hash(delta_string.as_bytes());

        let recovery_commitment =
            Self::commitment_scheme(recovery_pk).context("Generate recovery commitment")?;

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
    fn create(patches: Vec<DIDStatePatch>) -> AResult<(Operation, JWK, JWK)> {
        let update_keypair = Self::generate_key().context("generate update key pair")?;
        let recovery_keypair = Self::generate_key().context("Generate Recovery Key Pair")?;
        let update_pk =
            PublicKeyJwk::try_from(update_keypair.to_public()).context("Update public key")?;
        let recovery_pk =
            PublicKeyJwk::try_from(recovery_keypair.to_public()).context("Recovery public key")?;
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
    ) -> AResult<UpdateOperation> {
        let update_pk = PublicKeyJwk::try_from(update_key.to_public())
            .context("Convert update key to PublicKeyJwk for Update operation")?;
        let canonicalized_update_pk = Self::json_canonicalization_scheme(&update_pk)
            .context("Canonicalize update public key for reveal value for Deactivate operation")?;
        let update_reveal_value = Self::reveal_value(canonicalized_update_pk.as_bytes());

        ensure!(
            new_update_pk != &update_pk,
            "New update public key must be different."
        );

        let new_update_commitment =
            Self::commitment_scheme(new_update_pk).context("Generate new update commitment")?;

        let update_operation_delta_object = Delta {
            patches,
            update_commitment: new_update_commitment,
        };

        let delta_string = Self::json_canonicalization_scheme(&update_operation_delta_object)
            .context("Canonicalize Update Operation Delta Object")?;
        let delta_hash = Self::hash(delta_string.as_bytes());

        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = UpdateClaims {
            update_key: update_pk,
            delta_hash,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, update_key)
            .context("Sign Update Operation")?;
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
    ) -> AResult<Operation> {
        let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public())
            .context("Convert recovery key to PublicKeyJwk for Recover operation")?;
        ensure!(
            new_recovery_pk != &recovery_pk,
            "New recovery public key must be different."
        );
        let canonicalized_recovery_pk = Self::json_canonicalization_scheme(&recovery_pk)
            .context("Canonicalize recovery public key for reveal value for Recover operation")?;
        let recover_reveal_value = Self::reveal_value(canonicalized_recovery_pk.as_bytes());
        let new_update_commitment =
            Self::commitment_scheme(new_update_pk).context("Generate new update commitment")?;
        let new_recovery_commitment =
            Self::commitment_scheme(new_recovery_pk).context("Generate new update commitment")?;

        let recover_operation_delta_object = Delta {
            patches,
            update_commitment: new_update_commitment,
        };

        let delta_string = Self::json_canonicalization_scheme(&recover_operation_delta_object)
            .context("Canonicalize Recover Operation Delta Object")?;
        let delta_hash = Self::hash(delta_string.as_bytes());

        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = RecoveryClaims {
            recovery_commitment: new_recovery_commitment,
            recovery_key: recovery_pk,
            delta_hash,
            anchor_origin: None,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, recovery_key)
            .context("Sign Recover Operation")?;
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
    ) -> AResult<(Operation, JWK, JWK)> {
        let new_update_keypair = Self::generate_key().context("Generate New Update Key Pair")?;
        let new_update_pk = PublicKeyJwk::try_from(new_update_keypair.to_public())
            .context("Convert new update public key")?;

        let new_recovery_keypair =
            Self::generate_key().context("Generate New Recovery Key Pair")?;
        let new_recovery_pk = PublicKeyJwk::try_from(new_recovery_keypair.to_public())
            .context("Convert new recovery public key")?;

        let recover_op = Self::recover_existing(
            did_suffix,
            recovery_key,
            &new_update_pk,
            &new_recovery_pk,
            patches,
        )
        .context("Construct Recover Operation")?;
        Ok((recover_op, new_update_keypair, new_recovery_keypair))
    }

    /// Deactivate a Sidetree-based DID
    ///
    /// Construct a Deactivate Operation according to [Sidetree §11.4
    /// Deactivate][deactivate]. Returns the deactivate operation.
    ///
    /// [deactivate]: https://identity.foundation/sidetree/spec/v1.0.0/#deactivate
    fn deactivate(did_suffix: DIDSuffix, recovery_key: JWK) -> AResult<DeactivateOperation> {
        let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public())
            .context("Convert recovery key to PublicKeyJwk for Deactivate operation")?;
        let canonicalized_recovery_pk = Self::json_canonicalization_scheme(&recovery_pk).context(
            "Canonicalize recovery public key for reveal value for Deactivate operation",
        )?;
        let recover_reveal_value = Self::reveal_value(canonicalized_recovery_pk.as_bytes());
        let algorithm = Self::SIGNATURE_ALGORITHM;
        let claims = DeactivateClaims {
            did_suffix: did_suffix.clone(),
            recovery_key: recovery_pk,
        };
        let signed_data = ssi_jwt::encode_sign(algorithm, &claims, &recovery_key)
            .context("Sign Deactivate Operation")?;
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
    fn serialize_suffix_data(suffix_data: &SuffixData) -> AResult<DIDSuffix> {
        let string =
            Self::json_canonicalization_scheme(suffix_data).context("Canonicalize Suffix Data")?;
        let hash = Self::hash(string.as_bytes());
        Ok(DIDSuffix(hash))
    }

    /// Check that a DID Suffix looks valid
    fn validate_did_suffix(suffix: &DIDSuffix) -> AResult<()> {
        let bytes =
            base64::decode_config(&suffix.0, base64::URL_SAFE_NO_PAD).context("Decode Base64")?;
        ensure!(
            bytes.len() == 34,
            "Unexpected length for Sidetree DID Suffix: {}",
            bytes.len()
        );
        ensure!(
            &bytes[0..1] == MULTIHASH_SHA2_256_PREFIX && &bytes[1..2] == MULTIHASH_SHA2_256_SIZE,
            "Expected SHA2-256 prefix for Sidetree DID Suffix"
        );
        Ok(())
    }
}

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

/// Partially verified DID Create operation
///
/// Converted from [CreateOperation].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedCreateOperation {
    did_suffix: DIDSuffix,
    r#type: Option<String>,
    recovery_commitment: String,
    anchor_origin: Option<String>,
    hashed_delta: Delta,
}

/// Partially verified DID Create operation
///
/// Converted from [UpdateOperation].
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedUpdateOperation {
    reveal_value: String,
    signed_delta: Delta,
    signed_update_key: PublicKeyJwk,
}

/// Partially verified DID Recovery operation
///
/// Converted from [RecoverOperation].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedRecoverOperation {
    reveal_value: String,
    signed_delta: Delta,
    signed_recovery_commitment: String,
    signed_recovery_key: PublicKeyJwk,
    signed_anchor_origin: Option<String>,
}

/// Partially verified DID Deactivate operation
///
/// Converted from [DeactivateOperation].
#[derive(Debug, Clone)]
pub struct PartiallyVerifiedDeactivateOperation {
    signed_did_suffix: DIDSuffix,
    reveal_value: String,
    signed_recovery_key: PublicKeyJwk,
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
    fn partial_verify<S: Sidetree>(self) -> AResult<Self::PartiallyVerifiedForm>;
}

impl SidetreeOperation for Operation {
    type PartiallyVerifiedForm = PartiallyVerifiedOperation;

    fn partial_verify<S: Sidetree>(self) -> AResult<Self::PartiallyVerifiedForm> {
        Ok(match self {
            Operation::Create(op) => PartiallyVerifiedOperation::Create(
                op.partial_verify::<S>()
                    .context("Partial verify Create operation")?,
            ),
            Operation::Update(op) => PartiallyVerifiedOperation::Update(
                op.partial_verify::<S>()
                    .context("Partial verify Update operation")?,
            ),
            Operation::Recover(op) => PartiallyVerifiedOperation::Recover(
                op.partial_verify::<S>()
                    .context("Partial verify Recover operation")?,
            ),
            Operation::Deactivate(op) => PartiallyVerifiedOperation::Deactivate(
                op.partial_verify::<S>()
                    .context("Partial verify Deactivate operation")?,
            ),
        })
    }
}

fn ensure_reveal_commitment<S: Sidetree>(
    recovery_commitment: &str,
    reveal_value: &str,
    pk: &PublicKeyJwk,
) -> AResult<()> {
    let canonicalized_public_key =
        S::json_canonicalization_scheme(&pk).context("Canonicalize JWK")?;
    let commitment_value = canonicalized_public_key.as_bytes();
    let computed_reveal_value = S::reveal_value(commitment_value);
    ensure!(&computed_reveal_value == reveal_value);
    let computed_commitment =
        S::commitment_scheme(pk).context("Unable to compute public key commitment")?;
    ensure!(&computed_commitment == recovery_commitment);
    Ok(())
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
    ) -> Result<(), SidetreeError> {
        match self {
            PartiallyVerifiedOperation::Create(_) => {
                return Err(SidetreeError::CreateCannotFollow);
            }
            PartiallyVerifiedOperation::Update(update) => {
                let update_commitment = previous
                    .update_commitment()
                    .ok_or(SidetreeError::MissingUpdateCommitment)?;
                ensure_reveal_commitment::<S>(
                    update_commitment,
                    &update.reveal_value,
                    &update.signed_update_key,
                )?;
            }
            PartiallyVerifiedOperation::Recover(recover) => {
                let recovery_commitment = previous
                    .recovery_commitment()
                    .ok_or(SidetreeError::MissingRecoveryCommitment)?;
                ensure_reveal_commitment::<S>(
                    recovery_commitment,
                    &recover.reveal_value,
                    &recover.signed_recovery_key,
                )?;
            }
            PartiallyVerifiedOperation::Deactivate(deactivate) => {
                if let PartiallyVerifiedOperation::Create(create) = previous {
                    return Err(SidetreeError::DIDSuffixMismatch {
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
                    .ok_or(SidetreeError::MissingRecoveryCommitment)?;
                ensure_reveal_commitment::<S>(
                    recovery_commitment,
                    &deactivate.reveal_value,
                    &deactivate.signed_recovery_key,
                )?;
            }
        }
        Ok(())
    }
}

impl SidetreeOperation for CreateOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedCreateOperation;

    fn partial_verify<S: Sidetree>(self) -> AResult<PartiallyVerifiedCreateOperation> {
        let did = SidetreeDID::<S>::from_create_operation(&self)
            .context("Unable to derive DID from create operation")?;
        let did_suffix = DIDSuffix::from(did);
        let delta_string = S::json_canonicalization_scheme(&self.delta)
            .context("Unable to Canonicalize Update Operation Delta Object")?;
        let delta_hash = S::hash(delta_string.as_bytes());
        ensure!(
            delta_hash == self.suffix_data.delta_hash,
            "Delta hash mismatch"
        );
        Ok(PartiallyVerifiedCreateOperation {
            did_suffix,
            r#type: self.suffix_data.r#type,
            recovery_commitment: self.suffix_data.recovery_commitment,
            anchor_origin: self.suffix_data.anchor_origin,
            hashed_delta: self.delta,
        })
    }
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

    fn partial_verify<S: Sidetree>(self) -> AResult<PartiallyVerifiedUpdateOperation> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).
        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &UpdateClaims| {
                &claims.update_key
            })
            .context("Verify Signed Update Data")?;
        ensure!(
            header.algorithm == S::SIGNATURE_ALGORITHM,
            "Update Operation must use Sidetree's signature algorithm"
        );
        let canonicalized_public_key = S::json_canonicalization_scheme(&claims.update_key)
            .context("Canonicalize Update Key")?;
        let computed_reveal_value = S::reveal_value(canonicalized_public_key.as_bytes());
        ensure!(
            self.reveal_value == computed_reveal_value,
            "Reveal value must match hash of update key. Computed: {}. Found: {}",
            computed_reveal_value,
            self.reveal_value,
        );
        let delta_string = S::json_canonicalization_scheme(&self.delta)
            .context("Canonicalize Update Operation Delta Object")?;
        let delta_hash = S::hash(delta_string.as_bytes());
        ensure!(claims.delta_hash == delta_hash, "Delta hash mismatch");
        // Note: did_suffix is dropped, since it's not signed over.
        Ok(PartiallyVerifiedUpdateOperation {
            reveal_value: self.reveal_value,
            signed_delta: self.delta,
            signed_update_key: claims.update_key,
        })
    }
}

impl SidetreeOperation for RecoverOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedRecoverOperation;

    /// Partially verify a [RecoverOperation]
    fn partial_verify<S: Sidetree>(self) -> AResult<PartiallyVerifiedRecoverOperation> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).
        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &RecoveryClaims| {
                &claims.recovery_key
            })
            .context("Verify Signed Recover Data")?;
        ensure!(
            header.algorithm == S::SIGNATURE_ALGORITHM,
            "Recover Operation must use Sidetree's signature algorithm"
        );
        let canonicalized_public_key = S::json_canonicalization_scheme(&claims.recovery_key)
            .context("Canonicalize Recover Key")?;
        let computed_reveal_value = S::reveal_value(canonicalized_public_key.as_bytes());
        ensure!(
            self.reveal_value == computed_reveal_value,
            "Reveal value must match hash of recovery key. Computed: {}. Found: {}",
            computed_reveal_value,
            self.reveal_value,
        );
        let delta_string = S::json_canonicalization_scheme(&self.delta)
            .context("Canonicalize Recover Operation Delta Object")?;
        let delta_hash = S::hash(delta_string.as_bytes());
        ensure!(claims.delta_hash == delta_hash, "Delta hash mismatch");
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

impl SidetreeOperation for DeactivateOperation {
    type PartiallyVerifiedForm = PartiallyVerifiedDeactivateOperation;

    /// Partially verify a [DeactivateOperation]
    fn partial_verify<S: Sidetree>(self) -> AResult<PartiallyVerifiedDeactivateOperation> {
        // Verify JWS against public key in payload.
        // Then check public key against its hash (reveal value).

        let (header, claims) =
            jws_decode_verify_inner(&self.signed_data, |claims: &DeactivateClaims| {
                &claims.recovery_key
            })
            .context("Verify Signed Deactivation Data")?;
        ensure!(
            header.algorithm == S::SIGNATURE_ALGORITHM,
            "Deactivate Operation must use Sidetree's signature algorithm"
        );
        let canonicalized_public_key = S::json_canonicalization_scheme(&claims.recovery_key)
            .context("Canonicalize Recovery Key")?;
        let computed_reveal_value = S::reveal_value(canonicalized_public_key.as_bytes());
        ensure!(
            self.reveal_value == computed_reveal_value,
            "Reveal value must match hash of recovery key. Computed: {}. Found: {}",
            computed_reveal_value,
            self.reveal_value,
        );
        ensure!(self.did_suffix == claims.did_suffix, "DID Suffix mismatch");
        Ok(PartiallyVerifiedDeactivateOperation {
            signed_did_suffix: claims.did_suffix,
            reveal_value: self.reveal_value,
            signed_recovery_key: claims.recovery_key,
        })
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
    pub purposes: Vec<VerificationRelationship>,
}

impl TryFrom<JWK> for PublicKeyEntry {
    type Error = AError;
    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let id = jwk.thumbprint().context("Compute JWK thumbprint")?;
        let pkjwk = PublicKeyJwk::try_from(jwk.to_public()).context("Convert key")?;
        let public_key = PublicKey::PublicKeyJwk(pkjwk);
        Ok(PublicKeyEntry {
            id,
            r#type: VERIFICATION_METHOD_TYPE.to_owned(),
            controller: None,
            public_key,
            purposes: vec![
                VerificationRelationship::AssertionMethod,
                VerificationRelationship::Authentication,
                VerificationRelationship::KeyAgreement,
                VerificationRelationship::CapabilityInvocation,
                VerificationRelationship::CapabilityDelegation,
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

/// Payload object for JWS in [UpdateOperation]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClaims {
    /// Key matching previous Update Commitment
    pub update_key: PublicKeyJwk,

    /// [Hash](Sidetree::hash) of canonicalized [Update Operation Delta Object](Delta).
    pub delta_hash: String,
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

/// Payload object for JWS in [DeactivateOperation]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct DeactivateClaims {
    pub did_suffix: DIDSuffix,
    /// Key matching previous Recovery Commitment
    pub recovery_key: PublicKeyJwk,
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
    jwk: Value,
}

/// Error resulting from [converting JWK to PublicKeyJwk][PublicKeyJwk::try_from]
#[derive(ThisError, Debug)]
pub enum PublicKeyJwkFromJWKError {
    /// Unable to convert JWK to [Value]
    #[error("Unable to convert JWK to Value")]
    ToValue(#[from] serde_json::Error),
    /// Public Key JWK must not contain private key parameters (e.g. "d")
    #[error("Public Key JWK must not contain private key parameters")]
    PrivateKeyParameters,
}

/// Error resulting from attempting to convert [PublicKeyJwk] to JWK
#[derive(ThisError, Debug)]
pub enum JWKFromPublicKeyJwkError {
    /// Unable to convert [Value] to JWK
    #[error("Unable to convert Value to JWK")]
    FromValue(#[from] serde_json::Error),
}

impl TryFrom<JWK> for PublicKeyJwk {
    type Error = PublicKeyJwkFromJWKError;
    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let jwk_value = serde_json::to_value(jwk).map_err(PublicKeyJwkFromJWKError::ToValue)?;
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

impl<S: Sidetree> FromStr for SidetreeDID<S> {
    type Err = AError;
    fn from_str(did: &str) -> Result<Self, Self::Err> {
        let mut parts = did.split(':');
        ensure!(parts.next() == Some("did"), "Expected DID URI scheme");
        ensure!(parts.next() == Some(S::METHOD), "DID Method mismatch");
        if let Some(network) = S::NETWORK {
            ensure!(parts.next() == Some(network), "Sidetree network mismatch");
        }
        let did_suffix_str = parts
            .next()
            .ok_or_else(|| anyhow!("Missing Sidetree DID Suffix"))?;
        let did_suffix = DIDSuffix(did_suffix_str.to_string());
        S::validate_did_suffix(&did_suffix).context("Validate Sidetree DID Suffix")?;
        let create_operation_data_opt = parts.next();
        ensure!(
            parts.next().is_none(),
            "Unexpected data after Sidetree Long-Form DID"
        );
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
            write!(f, "{network}:")?;
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

impl<S: Sidetree> SidetreeDID<S> {
    /// Construct a [Long-Form Sidetree DID][lfdu] from a [Create Operation][CreateOperation]
    ///
    /// [lfdu]: https://identity.foundation/sidetree/spec/v1.0.0/#long-form-did-uris
    pub fn from_create_operation(create_operation: &CreateOperation) -> AResult<Self> {
        let op_json = S::json_canonicalization_scheme(&create_operation)
            .context("Canonicalize Create Operation")?;
        let op_string = S::data_encoding_scheme(op_json.as_bytes());

        let did_suffix = S::serialize_suffix_data(&create_operation.suffix_data)
            .context("Serialize DID Suffix Data")?;
        Ok(Self::Long {
            did_suffix,
            create_operation_data: op_string,
            _marker: PhantomData,
        })
    }
}

/// Convert a DID URL to an object id given a DID
///
/// Object id is an id of a [ServiceEndpointEntry] or [PublicKeyEntry].
fn did_url_to_id<S: Sidetree>(did_url: &str, did: &SidetreeDID<S>) -> AResult<String> {
    let did_string = did.to_string();
    let unprefixed = match did_url.strip_prefix(&did_string) {
        Some(s) => s,
        None => bail!("DID URL did not begin with expected DID"),
    };
    let fragment = match unprefixed.strip_prefix('#') {
        Some(s) => s,
        None => bail!("Expected DID URL with fragment"),
    };
    Ok(fragment.to_string())
}

impl<S: Sidetree> From<SidetreeDID<S>> for DIDSuffix {
    fn from(did: SidetreeDID<S>) -> DIDSuffix {
        match did {
            SidetreeDID::Short { did_suffix } => did_suffix,
            SidetreeDID::Long { did_suffix, .. } => did_suffix,
        }
    }
}

/// DID Resolver using ION/Sidetree REST API
#[derive(Debug, Clone, Default)]
pub struct HTTPSidetreeDIDResolver<S: Sidetree> {
    pub http_did_resolver: HTTPDIDResolver,
    pub _marker: PhantomData<S>,
}

impl<S: Sidetree> HTTPSidetreeDIDResolver<S> {
    pub fn new(sidetree_api_url: &str) -> Self {
        let identifiers_url = format!("{sidetree_api_url}identifiers/");
        Self {
            http_did_resolver: HTTPDIDResolver::new(&identifiers_url),
            _marker: PhantomData,
        }
    }
}

/// Sidetree DID Method client implementation
#[derive(Clone)]
pub struct SidetreeClient<S: Sidetree> {
    pub resolver: Option<HTTPSidetreeDIDResolver<S>>,
    pub endpoint: Option<String>,
}

impl<S: Sidetree> SidetreeClient<S> {
    pub fn new(api_url_opt: Option<String>) -> Self {
        let resolver_opt = api_url_opt
            .as_ref()
            .map(|url| HTTPSidetreeDIDResolver::new(url));
        Self {
            endpoint: api_url_opt,
            resolver: resolver_opt,
        }
    }
}

/// Check that a JWK is Secp256k1
pub fn is_secp256k1(jwk: &JWK) -> bool {
    matches!(jwk, JWK {params: ssi_jwk::Params::EC(ssi_jwk::ECParams { curve: Some(curve), ..}), ..} if curve == "secp256k1")
}

struct NoOpResolver;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for NoOpResolver {
    async fn resolve(
        &self,
        _did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        (
            ResolutionMetadata::from_error("Missing Sidetree API endpoint"),
            None,
            None,
        )
    }
}

fn new_did_state<S: Sidetree>(
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
    verification_key: Option<JWK>,
) -> AResult<(PublicKeyJwk, PublicKeyJwk, Vec<DIDStatePatch>)> {
    let update_key = update_key.ok_or_else(|| anyhow!("Missing required update key"))?;
    S::validate_key(&update_key).context("Validate update key")?;
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).context("Convert update key")?;
    let recovery_key = recovery_key.ok_or_else(|| anyhow!("Missing required recovery key"))?;
    S::validate_key(&recovery_key).context("Validate recovery key")?;
    let recovery_pk =
        PublicKeyJwk::try_from(recovery_key.to_public()).context("Convert recovery key")?;
    let mut patches = vec![];
    if let Some(verification_key) = verification_key {
        let public_key_entry = PublicKeyEntry::try_from(verification_key)
            .context("Convert JWK to public key entry")?;
        let document = DocumentState {
            public_keys: Some(vec![public_key_entry]),
            services: None,
        };
        let patch = DIDStatePatch::Replace { document };
        patches.push(patch);
    };
    Ok((update_pk, recovery_pk, patches))
}

fn b64len(s: &str) -> usize {
    base64::encode_config(s, base64::URL_SAFE_NO_PAD).len()
}

impl DIDStatePatch {
    /// Convert a [DID Document Operation][ddo] and DID to a Sidetree [DID State Patch][dsp].
    ///
    /// [ddp]: https://identity.foundation/did-registration/#diddocumentoperation
    /// [dsp]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
    fn try_from_with_did<S: Sidetree>(
        did_doc_op: DIDDocumentOperation,
        did: &SidetreeDID<S>,
    ) -> AResult<Self> {
        Ok(match did_doc_op {
            DIDDocumentOperation::SetDidDocument(_doc) => {
                bail!("setDidDocument not implemented")
            }
            DIDDocumentOperation::AddToDidDocument(_props) => {
                bail!("addToDidDocument not implemented")
            }
            DIDDocumentOperation::RemoveFromDidDocument(_props) => {
                bail!("removeFromDidDocument not implemented")
            }
            DIDDocumentOperation::SetVerificationMethod { vmm, purposes } => {
                let sub_id =
                    did_url_to_id(&vmm.id, did).context("Convert verification method id")?;
                let mut value =
                    serde_json::to_value(vmm).context("Convert verification method map")?;
                value["id"] = Value::String(sub_id);
                value["purposes"] = serde_json::to_value(purposes)
                    .context("Convert verification method purposes")?;
                let entry: PublicKeyEntry = serde_json::from_value(value)
                    .context("Convert verification method to Sidetree public key entry")?;
                // TODO: allow omitted controller property
                DIDStatePatch::AddPublicKeys {
                    public_keys: vec![entry],
                }
            }
            DIDDocumentOperation::SetService(service) => {
                let Service {
                    id,
                    type_,
                    service_endpoint,
                    property_set,
                } = service;
                ensure!(
                    !matches!(property_set, Some(map) if !map.is_empty()),
                    "Unexpected service properties"
                );
                let service_endpoint = match service_endpoint {
                    None => bail!("Missing endpoint for service"),
                    Some(OneOrMany::Many(_)) => bail!("Sidetree service must contain one endpoint"),
                    Some(OneOrMany::One(se)) => se,
                };
                let sub_id = did_url_to_id(&id, did).context("Convert service id")?;
                let service_type = match type_ {
                    OneOrMany::One(type_) => type_,
                    OneOrMany::Many(_) => bail!("Service must contain single type"),
                };
                ensure!(b64len(&service_type) <= 30, "Sidetree service type must contain no more than 30 Base64Url-encoded characters");
                ensure!(
                    b64len(&sub_id) <= 50,
                    "Sidetree service id must contain no more than 50 Base64Url-encoded characters"
                );
                let entry = ServiceEndpointEntry {
                    id: sub_id,
                    r#type: service_type,
                    service_endpoint,
                };
                DIDStatePatch::AddServices {
                    services: vec![entry],
                }
            }
            DIDDocumentOperation::RemoveVerificationMethod(did_url) => {
                let id = did_url.to_string();
                DIDStatePatch::RemovePublicKeys { ids: vec![id] }
            }
            DIDDocumentOperation::RemoveService(did_url) => {
                let id = did_url.to_string();
                DIDStatePatch::RemoveServices { ids: vec![id] }
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SidetreeAPIError {
    // List of error codes: https://github.com/decentralized-identity/sidetree/blob/v1.0.0/lib/core/versions/1.0/ErrorCode.ts
    pub code: String,
    pub message: Option<String>,
}

impl fmt::Display for SidetreeAPIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sidetree error {}", self.code)?;
        if let Some(ref message) = self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: Sidetree + Send + Sync> DIDMethod for SidetreeClient<S> {
    fn name(&self) -> &'static str {
        S::METHOD
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        match self.resolver {
            Some(ref res) => res,
            None => &NoOpResolver,
        }
    }

    fn create(&self, create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDCreate {
            recovery_key,
            update_key,
            verification_key,
            options,
        } = create;
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "create",
                option: opt.clone(),
            });
        }
        let (update_pk, recovery_pk, patches) =
            new_did_state::<S>(update_key, recovery_key, verification_key)
                .context("Prepare keys for DID creation")?;
        let operation = S::create_existing(&update_pk, &recovery_pk, patches)
            .context("Construct Create operation")?;
        let tx = Self::op_to_transaction(operation).context("Construct create transaction")?;
        Ok(tx)
    }

    /// <https://identity.foundation/sidetree/api/#sidetree-operations>
    async fn submit_transaction(&self, tx: DIDMethodTransaction) -> Result<Value, DIDMethodError> {
        let op = Self::op_from_transaction(tx)
            .context("Convert DID method transaction to Sidetree operation")?;
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("Missing Sidetree REST API endpoint"))?;
        let url = format!("{endpoint}operations/");
        let client = Client::builder().build().context("Build HTTP client")?;
        let resp = client
            .post(url)
            .json(&op)
            .header("Accept", "application/json")
            .header("User-Agent", crate::USER_AGENT)
            .send()
            .await
            .context("Send HTTP request")?;
        if let Err(e) = resp.error_for_status_ref() {
            let err: SidetreeAPIError = resp
                .json()
                .await
                .context("Transaction submit failed. Unable to read HTTP response JSON")?;
            return Err(anyhow!("Transaction submit failed: {}: {}", e, err).into());
        }
        if resp.content_length() == Some(0) {
            // Update operation may return empty body with 200 OK.
            return Ok(Value::Null);
        }
        let bytes = resp.bytes().await.context("Unable to read HTTP response")?;
        let resp_json: Value = serde_json::from_slice(&bytes).context(format!(
            "Unable to parse result as JSON: {}",
            String::from_utf8(bytes.to_vec()).context("Unable to parse result as UTF-8")?
        ))?;
        Ok(resp_json)
    }

    fn did_from_transaction(&self, tx: DIDMethodTransaction) -> Result<String, DIDMethodError> {
        let op = Self::op_from_transaction(tx)
            .context("Convert DID method transaction to Sidetree operation")?;
        let did = match op {
            Operation::Create(create_op) => SidetreeDID::<S>::from_create_operation(&create_op)
                .context("Derive DID from Create operation")?,
            Operation::Update(update_op) => SidetreeDID::Short {
                did_suffix: update_op.did_suffix,
            },
            Operation::Recover(recover_op) => SidetreeDID::Short {
                did_suffix: recover_op.did_suffix,
            },
            Operation::Deactivate(deactivate_op) => SidetreeDID::Short {
                did_suffix: deactivate_op.did_suffix,
            },
        };
        Ok(did.to_string())
    }

    fn update(&self, update: DIDUpdate) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDUpdate {
            did,
            update_key,
            new_update_key,
            operation,
            options,
        } = update;
        let did = SidetreeDID::<S>::from_str(&did).context("Parse Sidetree DID")?;
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "update",
                option: opt.clone(),
            });
        }
        let update_key = update_key.ok_or_else(|| anyhow!("Missing required new update key"))?;
        let new_update_key =
            new_update_key.ok_or_else(|| anyhow!("Missing required new update key"))?;
        S::validate_key(&new_update_key).context("Validate update key")?;
        let new_update_pk =
            PublicKeyJwk::try_from(new_update_key.to_public()).context("Convert new update key")?;
        let patches = vec![DIDStatePatch::try_from_with_did(operation, &did)
            .context("Convert DID document operation to Sidetree patch actions")?];
        let did_suffix = DIDSuffix::from(did);
        let update_operation = S::update(did_suffix, &update_key, &new_update_pk, patches)
            .context("Construct Update operation")?;
        let tx = Self::op_to_transaction(Operation::Update(update_operation))
            .context("Construct update transaction")?;
        Ok(tx)
    }

    fn recover(&self, recover: DIDRecover) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDRecover {
            did,
            recovery_key,
            new_recovery_key,
            new_update_key,
            new_verification_key,
            options,
        } = recover;
        let did = SidetreeDID::<S>::from_str(&did).context("Parse Sidetree DID")?;
        let did_suffix = DIDSuffix::from(did);
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "recover",
                option: opt.clone(),
            });
        }
        let recovery_key = recovery_key.ok_or_else(|| anyhow!("Missing required recovery key"))?;
        let (new_update_pk, new_recovery_pk, patches) =
            new_did_state::<S>(new_update_key, new_recovery_key, new_verification_key)
                .context("Prepare keys for DID recovery")?;
        let operation = S::recover_existing(
            did_suffix,
            &recovery_key,
            &new_update_pk,
            &new_recovery_pk,
            patches,
        )
        .context("Construct Recover operation")?;
        let tx = Self::op_to_transaction(operation).context("Construct recover transaction")?;
        Ok(tx)
    }

    fn deactivate(
        &self,
        deactivate: DIDDeactivate,
    ) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDDeactivate { did, key, options } = deactivate;
        let did = SidetreeDID::<S>::from_str(&did).context("Parse Sidetree DID")?;
        let recovery_key =
            key.ok_or_else(|| anyhow!("Missing required recovery key for DID deactivation"))?;
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "deactivate",
                option: opt.clone(),
            });
        }
        let did_suffix = DIDSuffix::from(did);
        let deactivate_operation = <S as Sidetree>::deactivate(did_suffix, recovery_key)
            .context("Construct DID Deactivate operation")?;
        let tx = Self::op_to_transaction(Operation::Deactivate(deactivate_operation))
            .context("Construct DID deactivate transaction")?;
        Ok(tx)
    }
}

impl<S: Sidetree> SidetreeClient<S> {
    fn op_to_transaction(op: Operation) -> AResult<DIDMethodTransaction> {
        let value = serde_json::to_value(op).context("Convert operation to value")?;
        Ok(DIDMethodTransaction {
            did_method: S::METHOD.to_string(),
            value: serde_json::json!({ "sidetreeOperation": value }),
        })
    }

    fn op_from_transaction(tx: DIDMethodTransaction) -> AResult<Operation> {
        let mut value = tx.value;
        let op_value = value
            .get_mut("sidetreeOperation")
            .ok_or_else(|| anyhow!("Missing sidetreeOperation property"))?
            .take();
        let op: Operation =
            serde_json::from_value(op_value).context("Convert value to operation")?;
        Ok(op)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: Sidetree + Send + Sync> DIDResolver for HTTPSidetreeDIDResolver<S> {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let _sidetree_did = match SidetreeDID::<S>::from_str(did) {
            Err(_e) => {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                );
            }
            Ok(did) => did,
        };
        self.http_did_resolver.resolve(did, input_metadata).await
    }
}

/// An error resulting from [jws_decode_verify_inner]
#[derive(ThisError, Debug)]
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
) -> Result<(Header, Claims), JWSDecodeVerifyError> {
    use ssi_jws::{decode_jws_parts, split_jws, verify_bytes, DecodedJWS};
    let (header_b64, payload_enc, signature_b64) =
        split_jws(jwt).map_err(JWSDecodeVerifyError::SplitJWS)?;
    let DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)
        .map_err(JWSDecodeVerifyError::DecodeJWSParts)?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(JWSDecodeVerifyError::DeserializeJWSPayload)?;
    let pk = get_key(&claims);
    let pk = JWK::try_from(pk.clone()).map_err(JWSDecodeVerifyError::JWKFromPublicKeyJwk)?;
    verify_bytes(header.algorithm, &signing_input, &pk, &signature)
        .map_err(JWSDecodeVerifyError::VerifyJWS)?;
    Ok((header, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Example;

    impl Sidetree for Example {
        fn generate_key() -> Result<JWK, SidetreeError> {
            let key = JWK::generate_secp256k1().context("Generate secp256k1 key")?;
            Ok(key)
        }
        fn validate_key(key: &JWK) -> Result<(), SidetreeError> {
            if !is_secp256k1(key) {
                return Err(anyhow!("Key must be Secp256k1").into());
            }
            Ok(())
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
    #[cfg(feature = "secp256k1")]
    fn test_longform_did_construction() {
        let create_operation = match &*CREATE_OPERATION {
            Operation::Create(op) => op,
            _ => panic!("Expected Create Operation"),
        };
        let did = SidetreeDID::<Example>::from_create_operation(create_operation).unwrap();
        assert_eq!(did.to_string(), LONGFORM_DID);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
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
    #[cfg(feature = "secp256k1")]
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
    #[cfg(feature = "secp256k1")]
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
