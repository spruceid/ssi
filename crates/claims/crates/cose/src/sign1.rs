use crate::{CborValue, CosePayload, CoseSignatureBytes};
use coset::{
    sig_structure_data, CborSerializable, CoseError, CoseSign1, Header, ProtectedHeader,
    TaggedCborSerializable,
};
use std::{borrow::Borrow, ops::Deref};

/// CBOR-encoded `COSE_Sign1` object.
///
/// This is the borrowed equivalent of [`CompactCoseSign1Buf`].
#[derive(Debug)]
#[repr(transparent)]
pub struct CompactCoseSign1([u8]);

impl CompactCoseSign1 {
    /// Creates a new CBOR-encoded `COSE_Sign1` object from a byte slice.
    ///
    /// The bytes are not actually checked. If the bytes are not describing
    /// a CBOR-encoded `COSE_Sign1` object it will be detected when the
    /// `decode` method is called.
    pub fn new(bytes: &[u8]) -> &Self {
        unsafe { std::mem::transmute(bytes) }
    }

    pub fn decode(&self, tagged: bool) -> Result<DecodedCoseSign1, CoseError> {
        let cose = if tagged {
            CoseSign1::from_tagged_slice(&self.0)?
        } else {
            CoseSign1::from_slice(&self.0)?
        };

        Ok(cose.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for CompactCoseSign1 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ToOwned for CompactCoseSign1 {
    type Owned = CompactCoseSign1Buf;

    fn to_owned(&self) -> Self::Owned {
        CompactCoseSign1Buf(self.0.to_owned())
    }
}

/// CBOR-encoded `COSE_Sign1` object buffer.
///
/// This is the owned equivalent of [`CompactCoseSign1`].
pub struct CompactCoseSign1Buf(Vec<u8>);

impl CompactCoseSign1Buf {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn encode(object: impl Into<CoseSign1>, tagged: bool) -> Self {
        if tagged {
            Self(TaggedCborSerializable::to_tagged_vec(object.into()).unwrap())
        } else {
            Self(CborSerializable::to_vec(object.into()).unwrap())
        }
    }

    pub fn as_compact(&self) -> &CompactCoseSign1 {
        CompactCoseSign1::new(self.0.as_slice())
    }
}

impl Deref for CompactCoseSign1Buf {
    type Target = CompactCoseSign1;

    fn deref(&self) -> &Self::Target {
        self.as_compact()
    }
}

impl Borrow<CompactCoseSign1> for CompactCoseSign1Buf {
    fn borrow(&self) -> &CompactCoseSign1 {
        self.as_compact()
    }
}

impl From<CborValue> for CompactCoseSign1Buf {
    fn from(value: CborValue) -> Self {
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer).unwrap();
        Self(buffer)
    }
}

impl AsRef<[u8]> for CompactCoseSign1Buf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for CompactCoseSign1Buf {
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
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> DecodedCoseSign1<U> {
        DecodedCoseSign1 {
            signing_bytes: self.signing_bytes.map(f),
            signature: self.signature,
        }
    }

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
#[derive(Clone, PartialEq)]
pub struct PayloadBytes<T = ()> {
    bytes: Vec<u8>,
    value: T,
}

impl PayloadBytes {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, value: () }
    }
}

impl<T: CosePayload> PayloadBytes<T> {
    pub fn new(value: T) -> Self {
        Self {
            bytes: value.payload_bytes().into_owned(),
            value,
        }
    }
}

impl<T> PayloadBytes<T> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> PayloadBytes<U> {
        let value = f(self.value, &self.bytes);
        PayloadBytes {
            bytes: self.bytes,
            value,
        }
    }

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

    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> UnsignedCoseSign1<U> {
        UnsignedCoseSign1 {
            protected: self.protected,
            unprotected: self.unprotected,
            payload: self.payload.map(f),
        }
    }

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
