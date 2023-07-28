use iref::IriBuf;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

/// `TezosMethod2021` Verification Method.
///
/// # Signature algorithm
///
/// The signature algorithm must be either:
/// - EdBlake2b,
/// - ESBlake2bK,
/// - ESBlake2b
///
/// # Key format
///
/// The public key is either stored using the `publicKeyJwk` or
/// `blockchainAccountId` properties. Because `blockchainAccountId` is just a
/// hash of the key, the public key must be embedded in the proof and passed to
/// the verification method (as its context).
///
/// In the proof, the public must be stored using the `publicKeyJwk` or
/// `publicKeyMultibase` properties. Here `publicKeyMultibase` is used in a
/// non-standard way, where the public key is encoded in base58 (`z` prefix) as
/// a thezos key (so without multicodec, contrarily to the specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "TezosMethod2021")]
pub struct TezosMethod2021 {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: IriBuf,

    #[serde(flatten)]
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "blockchainAccountId")]
    BlockchainAccountId(ssi_caips::caip10::BlockchainAccountId),
}
