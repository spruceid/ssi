use ssi_crypto::protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnySignatureProtocol {
    Direct,
    Base58Btc,
    Base58BtcMultibase,
    EthereumWallet,
}

pub enum AnyProtocolOutput {
    Direct(Vec<u8>),
    Base58Btc(String),
    Base58BtcMultibase(String),
    EthereumWallet(String),
}

#[derive(Debug, Clone, Copy)]
pub enum AnyProtocolOutputType {
    Direct,
    Base58Btc,
    Base58BtcMultibase,
    EthereumWallet,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid output")]
pub struct InvalidProtocolOutput(pub AnyProtocolOutputType);

impl TryFrom<AnyProtocolOutput> for Vec<u8> {
    type Error = InvalidProtocolOutput;

    fn try_from(value: AnyProtocolOutput) -> Result<Self, Self::Error> {
        match value {
            AnyProtocolOutput::Direct(bytes) => Ok(bytes),
            AnyProtocolOutput::Base58Btc(_) => {
                Err(InvalidProtocolOutput(AnyProtocolOutputType::Base58Btc))
            }
            AnyProtocolOutput::Base58BtcMultibase(_) => Err(InvalidProtocolOutput(
                AnyProtocolOutputType::Base58BtcMultibase,
            )),
            AnyProtocolOutput::EthereumWallet(_) => {
                Err(InvalidProtocolOutput(AnyProtocolOutputType::EthereumWallet))
            }
        }
    }
}

impl TryFrom<AnyProtocolOutput> for String {
    type Error = InvalidProtocolOutput;

    fn try_from(value: AnyProtocolOutput) -> Result<Self, Self::Error> {
        match value {
            AnyProtocolOutput::Direct(_) => {
                Err(InvalidProtocolOutput(AnyProtocolOutputType::Direct))
            }
            AnyProtocolOutput::Base58Btc(s) => Ok(s),
            AnyProtocolOutput::Base58BtcMultibase(s) => Ok(s),
            AnyProtocolOutput::EthereumWallet(s) => Ok(s),
        }
    }
}

impl ssi_crypto::SignatureProtocol for AnySignatureProtocol {
    type Output = AnyProtocolOutput;
}

impl From<()> for AnySignatureProtocol {
    fn from(value: ()) -> Self {
        Self::Direct
    }
}

impl From<protocol::Base58Btc> for AnySignatureProtocol {
    fn from(value: protocol::Base58Btc) -> Self {
        Self::Base58Btc
    }
}

impl From<protocol::Base58BtcMultibase> for AnySignatureProtocol {
    fn from(value: protocol::Base58BtcMultibase) -> Self {
        Self::Base58BtcMultibase
    }
}

impl From<protocol::EthereumWallet> for AnySignatureProtocol {
    fn from(value: protocol::EthereumWallet) -> Self {
        Self::EthereumWallet
    }
}
