use std::borrow::Cow;

use ssi_crypto::{protocol, MessageSignatureError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnySignatureProtocol {
    Direct,
    Base58Btc,
    Base58BtcMultibase,
    EthereumWallet,
    #[cfg(feature = "tezos")]
    TezosWallet,
}

impl ssi_crypto::SignatureProtocol<ssi_jwk::Algorithm> for AnySignatureProtocol {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        match self {
            Self::Direct => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(&(), bytes)
            }
            Self::Base58Btc => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                    &protocol::Base58Btc,
                    bytes,
                )
            }
            Self::Base58BtcMultibase => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                    &protocol::Base58BtcMultibase,
                    bytes,
                )
            }
            Self::EthereumWallet => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::prepare_message(
                    &protocol::EthereumWallet,
                    bytes,
                )
            }
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::algorithm::AnyBlake2b>::prepare_message(
                    &ssi_data_integrity_suites::tezos::TezosWallet,
                    bytes,
                )
            }
        }
    }

    fn encode_signature(
        &self,
        algorithm: ssi_jwk::Algorithm,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match self {
            Self::Direct => ().encode_signature(algorithm, signature),
            Self::Base58Btc => protocol::Base58Btc.encode_signature(algorithm, signature),
            Self::Base58BtcMultibase => {
                protocol::Base58BtcMultibase.encode_signature(algorithm, signature)
            }
            Self::EthereumWallet => protocol::EthereumWallet.encode_signature(algorithm, signature),
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                let algorithm: ssi_jwk::algorithm::AnyBlake2b = algorithm.try_into()?;
                ssi_data_integrity_suites::tezos::TezosWallet.encode_signature(algorithm, signature)
            }
        }
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, protocol::InvalidProtocolSignature> {
        match self {
            Self::Direct => ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                &(),
                encoded_signature,
            ),
            Self::Base58Btc => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                    &protocol::Base58Btc,
                    encoded_signature,
                )
            }
            Self::Base58BtcMultibase => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                    &protocol::Base58BtcMultibase,
                    encoded_signature,
                )
            }
            Self::EthereumWallet => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::Algorithm>::decode_signature(
                    &protocol::EthereumWallet,
                    encoded_signature,
                )
            }
            #[cfg(feature = "tezos")]
            Self::TezosWallet => {
                ssi_crypto::SignatureProtocol::<ssi_jwk::algorithm::AnyBlake2b>::decode_signature(
                    &ssi_data_integrity_suites::tezos::TezosWallet,
                    encoded_signature,
                )
            }
        }
    }
}

impl From<()> for AnySignatureProtocol {
    fn from(_value: ()) -> Self {
        Self::Direct
    }
}

impl From<protocol::Base58Btc> for AnySignatureProtocol {
    fn from(_value: protocol::Base58Btc) -> Self {
        Self::Base58Btc
    }
}

impl From<protocol::Base58BtcMultibase> for AnySignatureProtocol {
    fn from(_value: protocol::Base58BtcMultibase) -> Self {
        Self::Base58BtcMultibase
    }
}

impl From<protocol::EthereumWallet> for AnySignatureProtocol {
    fn from(_value: protocol::EthereumWallet) -> Self {
        Self::EthereumWallet
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos::TezosWallet> for AnySignatureProtocol {
    fn from(_value: ssi_data_integrity_suites::tezos::TezosWallet) -> Self {
        Self::TezosWallet
    }
}
