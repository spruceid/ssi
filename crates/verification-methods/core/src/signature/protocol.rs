use std::borrow::Cow;

use ssi_claims_core::MessageSignatureError;
use ssi_crypto::algorithm::{SignatureAlgorithmInstance, SignatureAlgorithmType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithProtocol<A, P>(pub A, pub P);

impl<A, P> WithProtocol<A, P> {
    pub fn new(algorithm: A, protocol: P) -> Self {
        Self(algorithm, protocol)
    }
}

impl<A: SignatureAlgorithmType, P: Copy> SignatureAlgorithmType for WithProtocol<A, P> {
    type Instance = WithProtocol<A::Instance, P>;
}

impl<I: SignatureAlgorithmInstance, P: Copy> SignatureAlgorithmInstance for WithProtocol<I, P> {
    type Algorithm = WithProtocol<I::Algorithm, P>;

    fn algorithm(&self) -> Self::Algorithm {
        WithProtocol(self.0.algorithm(), self.1)
    }
}

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
pub trait SignatureProtocol<A>: Copy {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        Cow::Borrowed(bytes)
    }

    fn prepare_messages<'b>(&self, bytes: &'b [Vec<u8>]) -> Cow<'b, [Vec<u8>]> {
        Cow::Borrowed(bytes)
    }

    fn encode_signature(
        &self,
        _algorithm: A,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(signature)
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

impl<A> SignatureProtocol<A> for () {}

/// Base58Btc Multibase protocol.
///
/// The signer must sent back the signature encoded with [multibase][1] using
/// the `Base58Btc` base.
///
/// [1]: <https://github.com/multiformats/multibase>
#[derive(Debug, Clone, Copy)]
pub struct Base58BtcMultibase;

impl Base58BtcMultibase {
    /// Encode the signature with multibase using the `Base58Btc` base as
    /// required by this protocol.
    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        multibase::encode(multibase::Base::Base58Btc, signature).into_bytes()
    }

    pub fn decode_signature(encoded_signature: &[u8]) -> Result<Vec<u8>, InvalidProtocolSignature> {
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

impl<A> SignatureProtocol<A> for Base58BtcMultibase {
    fn encode_signature(
        &self,
        _algorithm: A,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(Self::encode_signature(&signature))
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
#[derive(Debug, Clone, Copy)]
pub struct Base58Btc;

impl Base58Btc {
    /// Encode the signature in base58 (bitcoin alphabet) as required by this
    /// protocol.
    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        bs58::encode(signature).into_vec()
    }

    pub fn decode_signature(encoded_signature: &[u8]) -> Result<Vec<u8>, InvalidProtocolSignature> {
        bs58::decode(encoded_signature)
            .into_vec()
            .map_err(|_| InvalidProtocolSignature)
    }
}

impl<A> SignatureProtocol<A> for Base58Btc {
    /// Encode the signature in base58 (bitcoin alphabet) as required by this
    /// protocol.
    fn encode_signature(
        &self,
        _algorithm: A,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(Self::encode_signature(&signature))
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
/// The recovery ID in the signature must start at 27 instead of 0.
#[derive(Debug, Clone, Copy)]
pub struct EthereumWallet;

impl EthereumWallet {
    pub fn prepare_message(bytes: &[u8]) -> Vec<u8> {
        let mut result = format!("\x19Ethereum Signed Message:\n{}", bytes.len()).into_bytes();
        result.extend_from_slice(bytes);
        result
    }

    pub fn encode_signature(signature: &[u8]) -> Vec<u8> {
        assert_eq!(signature.len(), 65);
        let mut result = Vec::new();
        result.extend_from_slice(b"0x");
        result.resize(132, 0);

        // Encode without the recovery ID.
        hex::encode_to_slice(&signature[..64], &mut result[2..130]).unwrap();

        // Encode the recovery ID, offset by 27.
        let rec_id = signature[64] + 27;
        hex::encode_to_slice(std::slice::from_ref(&rec_id), &mut result[130..]).unwrap();

        // Send back the result.
        result
    }

    pub fn decode_signature(encoded_signature: &[u8]) -> Result<Vec<u8>, InvalidProtocolSignature> {
        let hex = encoded_signature
            .strip_prefix(b"0x")
            .ok_or(InvalidProtocolSignature)?;

        let mut signature = hex::decode(hex).map_err(|_| InvalidProtocolSignature)?;
        signature[64] -= 27; // Offset the recovery ID by -27.

        Ok(signature)
    }
}

impl<A> SignatureProtocol<A> for EthereumWallet {
    fn prepare_message<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        Cow::Owned(Self::prepare_message(bytes))
    }

    fn encode_signature(
        &self,
        _algorithm: A,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(Self::encode_signature(&signature))
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Self::decode_signature(encoded_signature).map(Cow::Owned)
    }
}
