use std::borrow::Cow;

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
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        Cow::Borrowed(bytes)
    }

    fn encode_signature(&self, signature: Vec<u8>) -> Vec<u8> {
        signature
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Ok(Cow::Borrowed(encoded_signature))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid protocol signature")]
pub struct InvalidProtocolSignature;

impl SignatureProtocol for () {}

/// Base58Btc Multibase protocol.
///
/// The signer must sent back the signature encoded with [multibase][1] using
/// the `Base58Btc` base.
///
/// [1]: <https://github.com/multiformats/multibase>
pub struct Base58BtcMultibase;

impl Base58BtcMultibase {
    /// Encode the signature with multibase using the `Base58Btc` base as
    /// required by this protocol.
    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        multibase::encode(multibase::Base::Base58Btc, signature).into_bytes()
    }

    pub fn decode_signature<'s>(
        encoded_signature: &'s [u8],
    ) -> Result<Vec<u8>, InvalidProtocolSignature> {
        let encoded_signature =
            std::str::from_utf8(encoded_signature).map_err(|_| InvalidProtocolSignature)?;
        let (base, signature) =
            multibase::decode(encoded_signature).map_err(|_| InvalidProtocolSignature)?;
        if base == multibase::Base::Base58Btc {
            Ok(signature)
        } else {
            Err(InvalidProtocolSignature)
        }
    }
}

impl SignatureProtocol for Base58BtcMultibase {
    fn encode_signature(&self, signature: Vec<u8>) -> Vec<u8> {
        Self::encode_signature(&signature)
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Self::decode_signature(encoded_signature).map(Cow::Owned)
    }
}

/// Base58Btc protocol.
///
/// The signer must sent back the signature encoded in base58 (bitcoin
/// alphabet).
pub struct Base58Btc;

impl Base58Btc {
    /// Encode the signature in base58 (bitcoin alphabet) as required by this
    /// protocol.
    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        bs58::encode(signature).into_vec()
    }

    pub fn decode_signature(encoded_signature: &[u8]) -> Result<Vec<u8>, InvalidProtocolSignature> {
        Ok(bs58::decode(encoded_signature)
            .into_vec()
            .map_err(|_| InvalidProtocolSignature)?)
    }
}

impl SignatureProtocol for Base58Btc {
    /// Encode the signature in base58 (bitcoin alphabet) as required by this
    /// protocol.
    fn encode_signature(&self, signature: Vec<u8>) -> Vec<u8> {
        Self::encode_signature(&signature)
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Self::decode_signature(encoded_signature).map(Cow::Owned)
    }
}

/// Ethereum Wallet protocol.
///
/// Used in combination with the `EthereumPersonalSignature2021` cryptographic
/// suite. The signer (the Ethereum Wallet) must prefix the message with
/// `\x19Ethereum Signed Message:\n` followed by the byte length of the message
/// and send back the signature encoded in hexadecimal, with a `0x` prefix.
pub struct EthereumWallet;

impl EthereumWallet {
    pub fn prepare_message(bytes: &[u8]) -> Vec<u8> {
        let mut result = format!("\x19Ethereum Signed Message:\n{}", bytes.len()).into_bytes();
        result.extend_from_slice(bytes);
        result
    }

    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(b"0x");
        result.resize(2 + signature.len() * 2, 0);
        hex::encode_to_slice(signature, &mut result[2..]).unwrap();
        result
    }

    pub fn decode_signature(encoded_signature: &[u8]) -> Result<Vec<u8>, InvalidProtocolSignature> {
        let hex = encoded_signature
            .strip_prefix(b"0x")
            .ok_or(InvalidProtocolSignature)?;
        hex::decode(hex).map_err(|_| InvalidProtocolSignature)
    }
}

impl SignatureProtocol for EthereumWallet {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        Cow::Owned(Self::prepare_message(bytes))
    }

    fn encode_signature(&self, signature: Vec<u8>) -> Vec<u8> {
        Self::encode_signature(&signature)
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Self::decode_signature(encoded_signature).map(Cow::Owned)
    }
}
