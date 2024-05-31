use iref::UriBuf;
use serde_json::Value;
use ssi_dids_core::{
    registration::{
        DIDCreate, DIDDeactivate, DIDMethodRegistry, DIDRecover, DIDTransactionCreationError,
        DIDTransactionError, DIDTransactionKind, DIDUpdate,
    },
    resolution::{self, DIDMethodResolver},
    DIDMethod,
};
use ssi_jwk::JWK;

use super::{
    DIDStatePatch, DIDSuffix, DocumentState, HTTPSidetreeDIDResolver, Operation, PublicKeyEntry,
    PublicKeyJwk, Sidetree, SidetreeAPIError, SidetreeDID,
};

#[derive(Debug, thiserror::Error)]
#[error("missing Sidetree REST API endpoint")]
pub struct MissingSidetreeApiEndpoint;

/// Sidetree DID Method client implementation
#[derive(Default, Clone)]
pub struct SidetreeClient<S: Sidetree> {
    pub resolver: Option<HTTPSidetreeDIDResolver<S>>,
    pub endpoint: Option<UriBuf>,
}

impl<S: Sidetree> SidetreeClient<S> {
    pub fn new(api_url_opt: Option<UriBuf>) -> Self {
        let resolver_opt = api_url_opt
            .as_deref()
            .map(|url| HTTPSidetreeDIDResolver::new(url));
        Self {
            endpoint: api_url_opt,
            resolver: resolver_opt,
        }
    }

    // fn did_from_transaction(&self, tx: DIDTransaction) -> Result<String, OperationFromTransactionError> {
    //     let op = Operation::from_transaction(tx.value)?;

    //     let did: SidetreeDID<S> = match op {
    //         Operation::Create(create_op) => create_op.to_sidetree_did(),
    //         Operation::Update(update_op) => SidetreeDID::Short {
    //             did_suffix: update_op.did_suffix,
    //         },
    //         Operation::Recover(recover_op) => SidetreeDID::Short {
    //             did_suffix: recover_op.did_suffix,
    //         },
    //         Operation::Deactivate(deactivate_op) => SidetreeDID::Short {
    //             did_suffix: deactivate_op.did_suffix,
    //         },
    //     };

    //     Ok(did.to_string())
    // }
}

impl<S: Sidetree> DIDMethod for SidetreeClient<S> {
    const DID_METHOD_NAME: &'static str = S::METHOD;
}

impl<S: Sidetree> DIDMethodResolver for SidetreeClient<S> {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match &self.resolver {
            Some(res) => {
                res.resolve_method_representation(method_specific_id, options)
                    .await
            }
            None => Err(resolution::Error::internal(MissingSidetreeApiEndpoint)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionSubmissionFailed {
    #[error("HTTP client creation failed: {0}")]
    HttpClient(reqwest::Error),

    #[error("unable to send HTTP request: {0}")]
    HttpRequest(reqwest::Error),

    #[error("server returned an error: {0}")]
    HttpServerApi(SidetreeAPIError),

    #[error("server returned an error: {0}")]
    HttpServer(reqwest::Error),

    #[error("unable to read HTTP response: {0}")]
    HttpResponse(reqwest::Error),

    #[error("unable to parse HTTP response as JSON")]
    Json,
}

impl<S: Sidetree> DIDMethodRegistry for SidetreeClient<S> {
    /// <https://identity.foundation/sidetree/api/#sidetree-operations>
    async fn submit_transaction(&self, tx: Value) -> Result<Value, DIDTransactionError> {
        let op = Operation::from_transaction(tx).map_err(DIDTransactionError::invalid)?;
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| DIDTransactionError::invalid(MissingSidetreeApiEndpoint))?;
        let url = format!("{}operations/", endpoint);
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| DIDTransactionError::failed(TransactionSubmissionFailed::HttpClient(e)))?;
        let resp = client
            .post(url)
            .json(&op)
            .header("Accept", "application/json")
            .header("User-Agent", crate::USER_AGENT)
            .send()
            .await
            .map_err(|e| {
                DIDTransactionError::failed(TransactionSubmissionFailed::HttpRequest(e))
            })?;
        if resp.error_for_status_ref().is_err() {
            let err: SidetreeAPIError = resp.json().await.map_err(|e| {
                DIDTransactionError::failed(TransactionSubmissionFailed::HttpServer(e))
            })?;
            return Err(DIDTransactionError::failed(
                TransactionSubmissionFailed::HttpServerApi(err),
            ));
        }
        if resp.content_length() == Some(0) {
            // Update operation may return empty body with 200 OK.
            return Ok(Value::Null);
        }
        let bytes = resp.bytes().await.map_err(|e| {
            DIDTransactionError::failed(TransactionSubmissionFailed::HttpResponse(e))
        })?;
        let resp_json: Value = serde_json::from_slice(&bytes)
            .map_err(|_| DIDTransactionError::failed(TransactionSubmissionFailed::Json))?;
        Ok(resp_json)
    }

    fn create(&self, create: DIDCreate) -> Result<Value, DIDTransactionCreationError> {
        let DIDCreate {
            recovery_key,
            update_key,
            verification_key,
            options,
        } = create;

        if let Some(opt) = options.keys().next() {
            return Err(DIDTransactionCreationError::UnsupportedOption {
                operation: DIDTransactionKind::Create,
                option: opt.clone(),
            });
        }

        let (update_pk, recovery_pk, patches) =
            new_did_state::<S>(update_key, recovery_key, verification_key)?;
        let operation: Operation = S::create_existing(&update_pk, &recovery_pk, patches)?;
        Ok(operation.into_transaction())
    }

    fn update(&self, update: DIDUpdate) -> Result<Value, DIDTransactionCreationError> {
        let DIDUpdate {
            did,
            update_key,
            new_update_key,
            operation,
            options,
        } = update;
        let did: SidetreeDID<S> = did.as_str().parse()?;

        if let Some(opt) = options.keys().next() {
            return Err(DIDTransactionCreationError::UnsupportedOption {
                operation: DIDTransactionKind::Update,
                option: opt.clone(),
            });
        }

        let update_key = update_key.ok_or(DIDTransactionCreationError::MissingRequiredUpdateKey)?;
        let new_update_key =
            new_update_key.ok_or(DIDTransactionCreationError::MissingRequiredNewUpdateKey)?;
        if !S::validate_key(&new_update_key) {
            return Err(DIDTransactionCreationError::InvalidUpdateKey);
        }
        let new_update_pk = PublicKeyJwk::try_from(new_update_key.to_public())
            .map_err(|_| DIDTransactionCreationError::InvalidUpdateKey)?;
        let patches = vec![DIDStatePatch::try_from_with_did(operation, &did)?];
        let did_suffix = DIDSuffix::from(did);
        let update_operation = S::update(did_suffix, &update_key, &new_update_pk, patches)?;
        Ok(Operation::Update(update_operation).into_transaction())
    }

    fn deactivate(&self, deactivate: DIDDeactivate) -> Result<Value, DIDTransactionCreationError> {
        let DIDDeactivate { did, key, options } = deactivate;
        let did: SidetreeDID<S> = did.as_str().parse()?;
        let recovery_key = key.ok_or(DIDTransactionCreationError::MissingRequiredRecoveryKey)?;
        if let Some(opt) = options.keys().next() {
            return Err(DIDTransactionCreationError::UnsupportedOption {
                operation: DIDTransactionKind::Deactivate,
                option: opt.clone(),
            });
        }
        let did_suffix = DIDSuffix::from(did);
        let deactivate_operation = <S as Sidetree>::deactivate(did_suffix, recovery_key)?;
        Ok(Operation::Deactivate(deactivate_operation).into_transaction())
    }

    fn recover(&self, recover: DIDRecover) -> Result<Value, DIDTransactionCreationError> {
        let DIDRecover {
            did,
            recovery_key,
            new_recovery_key,
            new_update_key,
            new_verification_key,
            options,
        } = recover;
        let did: SidetreeDID<S> = did.as_str().parse()?;
        let did_suffix = DIDSuffix::from(did);
        if let Some(opt) = options.keys().next() {
            return Err(DIDTransactionCreationError::UnsupportedOption {
                operation: DIDTransactionKind::Recover,
                option: opt.clone(),
            });
        }
        let recovery_key =
            recovery_key.ok_or(DIDTransactionCreationError::MissingRequiredRecoveryKey)?;
        let (new_update_pk, new_recovery_pk, patches) =
            new_did_state::<S>(new_update_key, new_recovery_key, new_verification_key)?;
        let operation = S::recover_existing(
            did_suffix,
            &recovery_key,
            &new_update_pk,
            &new_recovery_pk,
            patches,
        )?;
        Ok(operation.into_transaction())
    }
}

fn new_did_state<S: Sidetree>(
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
    verification_key: Option<JWK>,
) -> Result<(PublicKeyJwk, PublicKeyJwk, Vec<DIDStatePatch>), DIDTransactionCreationError> {
    let update_key = update_key.ok_or(DIDTransactionCreationError::MissingRequiredUpdateKey)?;
    if !S::validate_key(&update_key) {
        return Err(DIDTransactionCreationError::InvalidUpdateKey);
    }
    let update_pk = PublicKeyJwk::try_from(update_key.to_public())
        .map_err(|_| DIDTransactionCreationError::InvalidUpdateKey)?;
    let recovery_key =
        recovery_key.ok_or(DIDTransactionCreationError::MissingRequiredRecoveryKey)?;
    if !S::validate_key(&recovery_key) {
        return Err(DIDTransactionCreationError::InvalidRecoveryKey);
    }
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public())
        .map_err(|_| DIDTransactionCreationError::InvalidRecoveryKey)?;
    let mut patches = vec![];
    if let Some(verification_key) = verification_key {
        let public_key_entry = PublicKeyEntry::try_from(verification_key)
            .map_err(|_| DIDTransactionCreationError::InvalidVerificationKey)?;
        let document = DocumentState {
            public_keys: Some(vec![public_key_entry]),
            services: None,
        };
        let patch = DIDStatePatch::Replace { document };
        patches.push(patch);
    };
    Ok((update_pk, recovery_pk, patches))
}
