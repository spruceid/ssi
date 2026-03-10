use iref::Iri;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_dids_core::{document::{self, DIDVerificationMethod}, DIDURLBuf, DIDBuf};
use ssi_jwk::JWK;
use static_iref::iri;

/// Intermediate representation for a verification method accumulated during
/// event processing, before materialisation into the DID document.
pub(crate) struct PendingVm {
    pub(crate) counter: u64,
    pub(crate) payload: PendingVmPayload,
    /// For delegates: true if sigAuth. For attribute keys: true if sigAuth or enc purpose.
    pub(crate) is_sig_auth: bool,
}

pub(crate) enum PendingVmPayload {
    Delegate {
        blockchain_account_id: BlockchainAccountId,
    },
    AttributeKey {
        vm_type: VerificationMethodType,
        prop_name: &'static str,
        prop_value: serde_json::Value,
    },
}

/// Intermediate representation for a service endpoint accumulated during
/// event processing.
pub(crate) struct PendingService {
    pub(crate) counter: u64,
    pub(crate) service_type: String,
    pub(crate) endpoint: document::service::Endpoint,
}

/// Decode the delegate_type bytes32 field by trimming trailing zeros
pub(crate) fn decode_delegate_type(delegate_type: &[u8; 32]) -> &[u8] {
    let end = delegate_type
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &delegate_type[..end]
}

#[allow(clippy::large_enum_variant)]
pub enum VerificationMethod {
    EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf,
        controller: DIDBuf,
        public_key_jwk: JWK,
    },
    EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
    Eip712Method2021 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
}

impl VerificationMethod {
    pub fn id(&self) -> &ssi_dids_core::DIDURL {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { id, .. } => id,
            Self::EcdsaSecp256k1RecoveryMethod2020 { id, .. } => id,
            Self::Eip712Method2021 { id, .. } => id,
        }
    }

    pub fn type_(&self) -> VerificationMethodType {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { .. } => {
                VerificationMethodType::EcdsaSecp256k1VerificationKey2019
            }
            Self::EcdsaSecp256k1RecoveryMethod2020 { .. } => {
                VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020
            }
            Self::Eip712Method2021 { .. } => VerificationMethodType::Eip712Method2021,
        }
    }
}

#[derive(Clone, Copy)]
pub enum VerificationMethodType {
    EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
    Ed25519VerificationKey2020,
    X25519KeyAgreementKey2020,
    Eip712Method2021,
}

impl VerificationMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::Ed25519VerificationKey2020 => "Ed25519VerificationKey2020",
            Self::X25519KeyAgreementKey2020 => "X25519KeyAgreementKey2020",
            Self::Eip712Method2021 => "Eip712Method2021",
        }
    }

    pub fn iri(&self) -> &'static Iri {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"),
            Self::EcdsaSecp256k1RecoveryMethod2020 => iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
            Self::Ed25519VerificationKey2020 => iri!("https://w3id.org/security#Ed25519VerificationKey2020"),
            Self::X25519KeyAgreementKey2020 => iri!("https://w3id.org/security#X25519KeyAgreementKey2020"),
            Self::Eip712Method2021 => iri!("https://w3id.org/security#Eip712Method2021"),
        }
    }
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
                id,
                controller,
                public_key_jwk,
            } => Self {
                id,
                type_: "EcdsaSecp256k1VerificationKey2019".to_owned(),
                controller,
                properties: [(
                    "publicKeyJwk".into(),
                    serde_json::to_value(&public_key_jwk).unwrap(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "EcdsaSecp256k1RecoveryMethod2020".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::Eip712Method2021 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "Eip712Method2021".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
        }
    }
}
