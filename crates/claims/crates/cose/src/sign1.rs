use crate::{CborValue, CosePayload, CoseSignatureBytes};
use coset::{
    sig_structure_data, CborSerializable, CoseError, CoseSign1, Header, ProtectedHeader,
    TaggedCborSerializable,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, ops::Deref};

/// CBOR-encoded `COSE_Sign1` object.
///
/// This represents the raw CBOR bytes encoding a [`CoseSign1`] object. The
/// [`Self::decode`] method can be used to decode into a [`DecodedCoseSign1`]
/// (similar to `CoseSign1` but with extra information about the payload).
///
/// This is the borrowed equivalent of [`CoseSign1BytesBuf`].
#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[serde(transparent)]
pub struct CoseSign1Bytes([u8]);

impl CoseSign1Bytes {
    /// Creates a new CBOR-encoded `COSE_Sign1` object from a byte slice.
    ///
    /// The bytes are not actually checked. If the bytes are not describing
    /// a CBOR-encoded `COSE_Sign1` object it will be detected when the
    /// [`Self::decode`] method is called.
    pub fn new(bytes: &[u8]) -> &Self {
        unsafe { std::mem::transmute(bytes) }
    }

    /// Decodes the CBOR bytes into a [`DecodedCoseSign1`].
    pub fn decode(&self, tagged: bool) -> Result<DecodedCoseSign1, CoseError> {
        let cose = if tagged {
            CoseSign1::from_tagged_slice(&self.0)?
        } else {
            CoseSign1::from_slice(&self.0)?
        };

        Ok(cose.into())
    }

    /// Returns the raw CBOR bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for CoseSign1Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ToOwned for CoseSign1Bytes {
    type Owned = CoseSign1BytesBuf;

    fn to_owned(&self) -> Self::Owned {
        CoseSign1BytesBuf(self.0.to_owned())
    }
}

/// CBOR-encoded `COSE_Sign1` object buffer.
///
/// This represents the raw CBOR bytes encoding a [`CoseSign1`] object. The
/// [`CoseSign1Bytes::decode`] method can be used to decode into a
/// [`DecodedCoseSign1`] (similar to `CoseSign1` but with extra information
/// about the payload).
///
/// This is the owned equivalent of [`CoseSign1Bytes`].
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct CoseSign1BytesBuf(Vec<u8>);

impl CoseSign1BytesBuf {
    /// Creates a new CBOR-encoded `COSE_Sign1` object from a byte buffer.
    ///
    /// The bytes are not actually checked. If the bytes are not describing
    /// a CBOR-encoded `COSE_Sign1` object it will be detected when the
    /// [`CoseSign1Bytes::decode`] method is called.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Creates a new CBOR-encoded `COSE_Sign1` object by encoding the give
    /// [`CoseSign1`] value.
    ///
    /// If `tagged` is set to `true`, the CBOR value will be tagged.
    pub fn encode(object: impl Into<CoseSign1>, tagged: bool) -> Self {
        if tagged {
            Self(TaggedCborSerializable::to_tagged_vec(object.into()).unwrap())
        } else {
            Self(CborSerializable::to_vec(object.into()).unwrap())
        }
    }

    /// Borrows the value as a [`CoseSign1Bytes`].
    pub fn as_compact(&self) -> &CoseSign1Bytes {
        CoseSign1Bytes::new(self.0.as_slice())
    }
}

impl Deref for CoseSign1BytesBuf {
    type Target = CoseSign1Bytes;

    fn deref(&self) -> &Self::Target {
        self.as_compact()
    }
}

impl Borrow<CoseSign1Bytes> for CoseSign1BytesBuf {
    fn borrow(&self) -> &CoseSign1Bytes {
        self.as_compact()
    }
}

impl From<CborValue> for CoseSign1BytesBuf {
    fn from(value: CborValue) -> Self {
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer).unwrap();
        Self(buffer)
    }
}

impl AsRef<[u8]> for CoseSign1BytesBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for CoseSign1BytesBuf {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// Decoded `COSE_Sign1` object.
pub struct DecodedCoseSign1<T = ()> {
    /// Signing bytes.
    pub signing_bytes: UnsignedCoseSign1<T>,

    /// Signature.
    pub signature: CoseSignatureBytes,
}

impl<T> DecodedCoseSign1<T> {
    /// Maps the payload interpretation.
    ///
    /// This function can be used to decode the raw payload bytes into a
    /// proper typed value the application can work with.
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> DecodedCoseSign1<U> {
        DecodedCoseSign1 {
            signing_bytes: self.signing_bytes.map(f),
            signature: self.signature,
        }
    }

    /// Tries to map the payload interpretation.
    ///
    /// This function can be used to decode the raw payload bytes into a
    /// proper typed value the application can work with.
    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T, &[u8]) -> Result<U, E>,
    ) -> Result<DecodedCoseSign1<U>, E> {
        Ok(DecodedCoseSign1 {
            signing_bytes: self.signing_bytes.try_map(f)?,
            signature: self.signature,
        })
    }
}

impl From<CoseSign1> for DecodedCoseSign1 {
    fn from(value: CoseSign1) -> Self {
        Self {
            signing_bytes: UnsignedCoseSign1 {
                protected: value.protected,
                unprotected: value.unprotected,
                payload: PayloadBytes::from_bytes(value.payload.unwrap_or_default()),
            },
            signature: CoseSignatureBytes(value.signature),
        }
    }
}

impl<T> From<DecodedCoseSign1<T>> for CoseSign1 {
    fn from(value: DecodedCoseSign1<T>) -> Self {
        Self {
            protected: value.signing_bytes.protected,
            unprotected: value.signing_bytes.unprotected,
            payload: Some(value.signing_bytes.payload.into_bytes()),
            signature: value.signature.into_bytes(),
        }
    }
}

/// Payload and bytes.
///
/// Stores the payload value as interpreted by the application (type `T`) and
/// the original payload bytes.
///
/// The original payload bytes are always preserved since they can not always
/// be deterministically (or cheaply) reconstructed from the typed payload
/// value.
#[derive(Clone, PartialEq)]
pub struct PayloadBytes<T = ()> {
    /// Original payload bytes.
    bytes: Vec<u8>,

    /// Interpretation of the payload bytes.
    value: T,
}

impl PayloadBytes {
    /// Creates a new `PayloadBytes` from the bytes.
    ///
    /// The interpretation of the bytes will be unit `()`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, value: () }
    }
}

impl<T: CosePayload> PayloadBytes<T> {
    /// Creates a new `PayloadBytes` from the payload, using
    /// [`CosePayload::payload_bytes`] to reconstruct the payload bytes.
    pub fn new(value: T) -> Self {
        Self {
            bytes: value.payload_bytes().into_owned(),
            value,
        }
    }
}

impl<T> PayloadBytes<T> {
    /// Returns the bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Maps the payload interpretation.
    ///
    /// This function can be used to decode the raw payload bytes into a
    /// proper typed value the application can work with.
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> PayloadBytes<U> {
        let value = f(self.value, &self.bytes);
        PayloadBytes {
            bytes: self.bytes,
            value,
        }
    }

    /// Tries to map the payload interpretation.
    ///
    /// This function can be used to decode the raw payload bytes into a
    /// proper typed value the application can work with.
    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T, &[u8]) -> Result<U, E>,
    ) -> Result<PayloadBytes<U>, E> {
        let value = f(self.value, &self.bytes)?;
        Ok(PayloadBytes {
            bytes: self.bytes,
            value,
        })
    }

    /// Forgets about the payload interpretation and returns the raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<T> Deref for PayloadBytes<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> Borrow<T> for PayloadBytes<T> {
    fn borrow(&self) -> &T {
        &self.value
    }
}

/// `COSE_Sign1` object without the signature.
#[derive(Clone, PartialEq)]
pub struct UnsignedCoseSign1<T> {
    /// Protected header.
    pub protected: ProtectedHeader,

    /// Unprotected header.
    pub unprotected: Header,

    /// Payload.
    pub payload: PayloadBytes<T>,
}

impl<T> UnsignedCoseSign1<T> {
    /// Returns the bytes that will be signed.
    pub fn tbs_data(&self, aad: &[u8]) -> Vec<u8> {
        sig_structure_data(
            coset::SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            self.payload.as_bytes(),
        )
    }

    /// Maps the payload interpretation.
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> UnsignedCoseSign1<U> {
        UnsignedCoseSign1 {
            protected: self.protected,
            unprotected: self.unprotected,
            payload: self.payload.map(f),
        }
    }

    /// Tries to map the payload interpretation.
    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T, &[u8]) -> Result<U, E>,
    ) -> Result<UnsignedCoseSign1<U>, E> {
        Ok(UnsignedCoseSign1 {
            protected: self.protected,
            unprotected: self.unprotected,
            payload: self.payload.try_map(f)?,
        })
    }
}
