/// Signature protocol.
///
/// Specifies how the client and signer communicates together to produce a
/// signature. This includes:
/// - how to encode the message sent to the signer,
/// - what transformation must be operated on the message by the signer,
/// - how to encode the signature to send back to the client.
///
/// For instance when using the `EthereumPersonalSignature2021` cryptographic
/// suite the [`EthereumWallet`] protocol applies where:
/// - the signer (the Ethereum Wallet) must prefix the message with
///   `\x19Ethereum Signed Message:\n`,
/// - send back the signature encoded in hexadecimal.
///
/// The simplest protocol is described by the unit `()` type, where the raw
/// message is transmitted to the signer, which must sign it and return the
/// raw bytes.
pub trait SignatureProtocol {
    type Output;
}

impl SignatureProtocol for () {
    type Output = Vec<u8>;
}

/// Base58Btc Multibase protocol.
///
/// The signer must sent back the signature encoded with [multibase][1] using
/// the `Base58Btc` base.
///
/// [1]: <https://github.com/multiformats/multibase>
pub struct Base58BtcMultibase;

impl SignatureProtocol for Base58BtcMultibase {
    /// Base58Btc-Multibase-encoded signature.
    type Output = String;
}

impl Base58BtcMultibase {
    /// Encode the signature with multibase using the `Base58Btc` base as
    /// required by this protocol.
    pub fn encode(signature: &[u8]) -> String {
        multibase::encode(multibase::Base::Base58Btc, signature)
    }
}

/// Base58Btc protocol.
///
/// The signer must sent back the signature encoded in base58 (bitcoin
/// alphabet).
pub struct Base58Btc;

impl SignatureProtocol for Base58Btc {
    /// Base58Btc-encoded signature.
    type Output = String;
}

impl Base58Btc {
    /// Encode the signature in base58 (bitcoin alphabet) as required by this
    /// protocol.
    pub fn encode(signature: &[u8]) -> String {
        bs58::encode(signature).into_string()
    }

    pub fn decode(signature: &str) -> Result<Vec<u8>, bs58::decode::Error> {
        bs58::decode(signature).into_vec()
    }
}

/// Ethereum Wallet protocol.
///
/// Used in combination with the `EthereumPersonalSignature2021` cryptographic
/// suite. The signer (the Ethereum Wallet) must prefix the message with
/// `\x19Ethereum Signed Message:\n` and send back the signature encoded in
/// hexadecimal, with a `0x` prefix.
pub struct EthereumWallet;

impl SignatureProtocol for EthereumWallet {
    /// Hex-encoded (with `0x` prefix) signature.
    type Output = String;
}
