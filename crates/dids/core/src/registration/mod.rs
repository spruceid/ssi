//! DID Registration & Recovery.
//!
//! See: <https://identity.foundation/did-registration>

use core::fmt;
use std::{borrow::Cow, collections::HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_jwk::JWK;
use ssi_verification_methods_core::ProofPurpose;

use crate::{
    document::{self, DIDVerificationMethod, Service},
    DIDBuf, DIDMethod, DIDURLBuf,
};

/// DID Document Operation
///
/// This should represent [didDocument][dd] and [didDocumentOperation][ddo] specified by DID
/// Registration.
///
/// [dd]: https://identity.foundation/did-registration/#diddocumentoperation
/// [ddo]: https://identity.foundation/did-registration/#diddocument
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "didDocumentOperation", content = "didDocument")]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum DIDDocumentOperation {
    /// Set the contents of the DID document
    ///
    /// setDidDocument operation defined by DIF DID Registration
    SetDidDocument(document::Represented),

    /// Add properties to the DID document
    ///
    /// addToDidDocument operation defined by DIF DID Registration
    AddToDidDocument(HashMap<String, Value>),

    /// Remove properties from the DID document
    ///
    /// removeFromDidDocument operation defined by DIF Registration
    RemoveFromDidDocument(Vec<String>),

    /// Add or update a verification method in the DID document
    SetVerificationMethod {
        vmm: DIDVerificationMethod,
        purposes: Vec<ProofPurpose>,
    },

    /// Add or update a service map in the DID document
    SetService(Service),

    /// Remove a verification method in the DID document
    RemoveVerificationMethod(DIDURLBuf),

    /// Add or update a service map in the DID document
    RemoveService(DIDURLBuf),
}

#[derive(Debug)]
pub enum DIDDocumentOperationKind {
    SetDidDocument,
    AddToDidDocument,
    RemoveFromDidDocument,
    SetVerificationMethod,
    SetService,
    RemoveVerificationMethod,
    RemoveService,
}

impl DIDDocumentOperationKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SetDidDocument => "setDidDocument",
            Self::AddToDidDocument => "addToDidDocument",
            Self::RemoveFromDidDocument => "removeFromDidDocument",
            Self::SetVerificationMethod => "setVerificationMethod",
            Self::SetService => "setService",
            Self::RemoveVerificationMethod => "removeVerificationMethod",
            Self::RemoveService => "removeService",
        }
    }
}

impl fmt::Display for DIDDocumentOperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

/// DID Create Operation.
///
/// <https://identity.foundation/did-registration/#create>
pub struct DIDCreate {
    pub update_key: Option<JWK>,
    pub recovery_key: Option<JWK>,
    pub verification_key: Option<JWK>,
    pub options: HashMap<String, Value>,
}

/// DID Update Operation.
///
/// <https://identity.foundation/did-registration/#update>
pub struct DIDUpdate {
    pub did: DIDBuf,
    pub update_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub operation: DIDDocumentOperation,
    pub options: HashMap<String, Value>,
}

/// DID Deactivate Operation.
///
/// <https://identity.foundation/did-registration/#deactivate>
pub struct DIDDeactivate {
    pub did: DIDBuf,
    pub key: Option<JWK>,
    pub options: HashMap<String, Value>,
}

/// DID Recover Operation.
///
/// <https://www.w3.org/TR/did-core/#did-recovery>
pub struct DIDRecover {
    pub did: DIDBuf,
    pub recovery_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub new_recovery_key: Option<JWK>,
    pub new_verification_key: Option<JWK>,
    pub options: HashMap<String, Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum DIDTransactionError {
    #[error("unsupported DID method `{0}`")]
    UnsupportedDIDMethod(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("transaction failed: {0}")]
    Failed(String),
}

impl DIDTransactionError {
    pub fn invalid(error: impl ToString) -> Self {
        Self::InvalidTransaction(error.to_string())
    }

    pub fn failed(error: impl ToString) -> Self {
        Self::Failed(error.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DIDTransactionCreationError {
    #[error("unimplemented transaction `{0}`")]
    UnimplementedTransaction(DIDTransactionKind),

    #[error("unimplemented DID document operation: {0}")]
    UnimplementedDocumentOperation(DIDDocumentOperationKind),

    #[error("unsupported DID method `{0}`")]
    UnsupportedDIDMethod(String),

    #[error("unsupported option `{option}` for {operation} operation")]
    UnsupportedOption {
        operation: DIDTransactionKind,
        option: String,
    },

    #[error("unsupported service property")]
    UnsupportedServiceProperty,

    #[error("missing required update key")]
    MissingRequiredUpdateKey,

    #[error("missing required new update key")]
    MissingRequiredNewUpdateKey,

    #[error("missing required recovery key")]
    MissingRequiredRecoveryKey,

    #[error("invalid update key")]
    InvalidUpdateKey,

    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    #[error("invalid verification key")]
    InvalidVerificationKey,

    #[error("same update and recovery keys")]
    SameUpdateAndRecoveryKeys,

    #[error("update key unchanged")]
    UpdateKeyUnchanged,

    #[error("recovery key unchanged")]
    RecoveryKeyUnchanged,

    #[error("key generation failed")]
    KeyGenerationFailed,

    #[error("invalid DID")]
    InvalidDID,

    #[error("invalid DID URL")]
    InvalidDIDURL,

    #[error("invalid verification method")]
    InvalidVerificationMethod,

    #[error("signature failed")]
    SignatureFailed,

    #[error("missing service endpoint")]
    MissingServiceEndpoint,

    #[error("ambiguous service endpoint")]
    AmbiguousServiceEndpoint,

    #[error("ambiguous service type")]
    AmbiguousServiceType,

    #[error("unsupported service: {reason}")]
    UnsupportedService { reason: Cow<'static, str> },

    #[error("{0}")]
    Internal(String),
}

impl DIDTransactionCreationError {
    pub fn internal(e: impl ToString) -> Self {
        Self::Internal(e.to_string())
    }
}

#[derive(Debug)]
pub enum DIDTransactionKind {
    Create,
    Update,
    Deactivate,
    Recover,
}

impl DIDTransactionKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Deactivate => "deactivate",
            Self::Recover => "recover",
        }
    }
}

impl fmt::Display for DIDTransactionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

pub struct DIDTransaction {
    /// DID method name.
    pub did_method: String,

    /// Method-specific transaction data.
    pub value: Value,
}

impl DIDTransaction {
    pub fn new(did_method: String, value: Value) -> Self {
        Self { did_method, value }
    }
}

pub trait DIDRegistry {
    #[allow(async_fn_in_trait)]
    async fn submit_transaction(
        &self,
        transaction: DIDTransaction,
    ) -> Result<Value, DIDTransactionError>;

    /// Create DID.
    fn create(
        &self,
        _method: &str,
        _create: DIDCreate,
    ) -> Result<DIDTransaction, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Create,
        ))
    }

    /// Update DID.
    fn update(&self, _update: DIDUpdate) -> Result<DIDTransaction, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Update,
        ))
    }

    /// Deactivate DID.
    fn deactivate(
        &self,
        _deactivate: DIDDeactivate,
    ) -> Result<DIDTransaction, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Deactivate,
        ))
    }

    /// Recover DID.
    fn recover(&self, _recover: DIDRecover) -> Result<DIDTransaction, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Recover,
        ))
    }
}

pub trait DIDMethodRegistry: DIDMethod {
    /// Submit a transaction.
    #[allow(async_fn_in_trait)]
    async fn submit_transaction(&self, transaction: Value) -> Result<Value, DIDTransactionError>;

    /// Create DID.
    fn create(&self, _create: DIDCreate) -> Result<Value, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Create,
        ))
    }

    /// Update DID.
    fn update(&self, _update: DIDUpdate) -> Result<Value, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Update,
        ))
    }

    /// Deactivate DID.
    fn deactivate(&self, _deactivate: DIDDeactivate) -> Result<Value, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Deactivate,
        ))
    }

    /// Recover DID.
    fn recover(&self, _recover: DIDRecover) -> Result<Value, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Recover,
        ))
    }
}

impl<M: DIDMethodRegistry> DIDRegistry for M {
    #[allow(async_fn_in_trait)]
    async fn submit_transaction(
        &self,
        transaction: DIDTransaction,
    ) -> Result<Value, DIDTransactionError> {
        if transaction.did_method == Self::DID_METHOD_NAME {
            DIDMethodRegistry::submit_transaction(self, transaction.value).await
        } else {
            Err(DIDTransactionError::UnsupportedDIDMethod(
                transaction.did_method,
            ))
        }
    }

    /// Create DID.
    fn create(
        &self,
        method: &str,
        create: DIDCreate,
    ) -> Result<DIDTransaction, DIDTransactionCreationError> {
        if method == Self::DID_METHOD_NAME {
            Ok(DIDTransaction::new(
                Self::DID_METHOD_NAME.to_owned(),
                DIDMethodRegistry::create(self, create)?,
            ))
        } else {
            Err(DIDTransactionCreationError::UnsupportedDIDMethod(
                method.to_owned(),
            ))
        }
    }

    /// Update DID.
    fn update(&self, update: DIDUpdate) -> Result<DIDTransaction, DIDTransactionCreationError> {
        if update.did.method_name() == Self::DID_METHOD_NAME {
            Ok(DIDTransaction::new(
                Self::DID_METHOD_NAME.to_owned(),
                DIDMethodRegistry::update(self, update)?,
            ))
        } else {
            Err(DIDTransactionCreationError::UnsupportedDIDMethod(
                update.did.method_name().to_owned(),
            ))
        }
    }

    /// Deactivate DID.
    fn deactivate(
        &self,
        deactivate: DIDDeactivate,
    ) -> Result<DIDTransaction, DIDTransactionCreationError> {
        if deactivate.did.method_name() == Self::DID_METHOD_NAME {
            Ok(DIDTransaction::new(
                Self::DID_METHOD_NAME.to_owned(),
                DIDMethodRegistry::deactivate(self, deactivate)?,
            ))
        } else {
            Err(DIDTransactionCreationError::UnsupportedDIDMethod(
                deactivate.did.method_name().to_owned(),
            ))
        }
    }

    /// Recover DID.
    fn recover(&self, _recover: DIDRecover) -> Result<DIDTransaction, DIDTransactionCreationError> {
        Err(DIDTransactionCreationError::UnimplementedTransaction(
            DIDTransactionKind::Recover,
        ))
    }
}
