use std::borrow::Cow;

use ssi_crypto::protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnySignatureProtocol {
    Direct,
    Base58Btc,
    Base58BtcMultibase,
    EthereumWallet,
}

impl ssi_crypto::SignatureProtocol for AnySignatureProtocol {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        match self {
            Self::Direct => ().prepare_message(bytes),
            Self::Base58Btc => protocol::Base58Btc.prepare_message(bytes),
            Self::Base58BtcMultibase => protocol::Base58BtcMultibase.prepare_message(bytes),
            Self::EthereumWallet => protocol::EthereumWallet.prepare_message(bytes),
        }
    }

    fn encode_signature(&self, signature: Vec<u8>) -> Vec<u8> {
        match self {
            Self::Direct => ().encode_signature(signature),
            Self::Base58Btc => protocol::Base58Btc.encode_signature(signature),
            Self::Base58BtcMultibase => protocol::Base58BtcMultibase.encode_signature(signature),
            Self::EthereumWallet => protocol::EthereumWallet.encode_signature(signature),
        }
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, protocol::InvalidProtocolSignature> {
        match self {
            Self::Direct => ().decode_signature(encoded_signature),
            Self::Base58Btc => protocol::Base58Btc.decode_signature(encoded_signature),
            Self::Base58BtcMultibase => {
                protocol::Base58BtcMultibase.decode_signature(encoded_signature)
            }
            Self::EthereumWallet => protocol::EthereumWallet.decode_signature(encoded_signature),
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
