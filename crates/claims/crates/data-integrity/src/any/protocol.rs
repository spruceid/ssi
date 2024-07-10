use std::borrow::Cow;

use ssi_claims_core::MessageSignatureError;
use ssi_verification_methods::{protocol, SignatureProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnyProtocol {
    None,
    Base58Btc,
    Base58BtcMultibase,
    EthereumWallet,
    #[cfg(feature = "tezos")]
    TezosWallet,
}

impl SignatureProtocol<ssi_crypto::Algorithm> for AnyProtocol {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        match self {
            Self::None => SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(&(), bytes),
            Self::Base58Btc => SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                &protocol::Base58Btc,
                bytes,
            ),
            Self::Base58BtcMultibase => SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                &protocol::Base58BtcMultibase,
                bytes,
            ),
            Self::EthereumWallet => SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                &protocol::EthereumWallet,
                bytes,
            ),
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                SignatureProtocol::<ssi_crypto::algorithm::AnyBlake2b>::prepare_message(
                    &ssi_data_integrity_suites::tezos::TezosWallet,
                    bytes,
                )
            }
        }
    }

    fn encode_signature(
        &self,
        algorithm: ssi_crypto::Algorithm,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match self {
            Self::None => SignatureProtocol::<ssi_crypto::Algorithm>::encode_signature(
                &(),
                algorithm,
                signature,
            ),
            Self::Base58Btc => SignatureProtocol::<ssi_crypto::Algorithm>::encode_signature(
                &protocol::Base58Btc,
                algorithm,
                signature,
            ),
            Self::Base58BtcMultibase => {
                SignatureProtocol::<ssi_crypto::Algorithm>::encode_signature(
                    &protocol::Base58BtcMultibase,
                    algorithm,
                    signature,
                )
            }
            Self::EthereumWallet => SignatureProtocol::<ssi_crypto::Algorithm>::encode_signature(
                &protocol::EthereumWallet,
                algorithm,
                signature,
            ),
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                let algorithm: ssi_crypto::algorithm::AnyBlake2b = algorithm.try_into()?;
                ssi_data_integrity_suites::tezos::TezosWallet.encode_signature(algorithm, signature)
            }
        }
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, protocol::InvalidProtocolSignature> {
        match self {
            Self::None => {
                SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(&(), encoded_signature)
            }
            Self::Base58Btc => SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                &protocol::Base58Btc,
                encoded_signature,
            ),
            Self::Base58BtcMultibase => SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                &protocol::Base58BtcMultibase,
                encoded_signature,
            ),
            Self::EthereumWallet => SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                &protocol::EthereumWallet,
                encoded_signature,
            ),
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                SignatureProtocol::<ssi_crypto::algorithm::AnyBlake2b>::decode_signature(
                    &ssi_data_integrity_suites::tezos::TezosWallet,
                    encoded_signature,
                )
            }
        }
    }
}

impl From<()> for AnyProtocol {
    fn from(_value: ()) -> Self {
        Self::None
    }
}

impl From<protocol::Base58Btc> for AnyProtocol {
    fn from(_value: protocol::Base58Btc) -> Self {
        Self::Base58Btc
    }
}

impl From<protocol::Base58BtcMultibase> for AnyProtocol {
    fn from(_value: protocol::Base58BtcMultibase) -> Self {
        Self::Base58BtcMultibase
    }
}

impl From<protocol::EthereumWallet> for AnyProtocol {
    fn from(_value: protocol::EthereumWallet) -> Self {
        Self::EthereumWallet
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos::TezosWallet> for AnyProtocol {
    fn from(_value: ssi_data_integrity_suites::tezos::TezosWallet) -> Self {
        Self::TezosWallet
    }
}
