//! CBOR Object Signing and Encryption ([COSE]) implementation based on
//! [`coset`].
//!
//! [COSE]: <https://datatracker.ietf.org/doc/html/rfc8152>
//! [`coset`]: <https://crates.io/crates/coset>
use coset::sig_structure_data;
use ssi_claims_core::SignatureError;
use std::borrow::Cow;
use std::ops::Deref;

pub use coset;
pub use coset::{CoseError, CoseKey, CoseSign1, Header, Label, ProtectedHeader};

pub type ContentType = coset::RegisteredLabel<coset::iana::CoapContentFormat>;

pub use ciborium;
pub use ciborium::Value as CborValue;

pub mod key;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

pub mod algorithm;

/// Compact COSE_Sign1 byte slice.
#[derive(Debug)]
#[repr(transparent)]
pub struct CompactCoseSign1([u8]);

impl CompactCoseSign1 {
    pub fn new(bytes: &[u8]) -> &Self {
        unsafe { std::mem::transmute(bytes) }
    }

    pub fn decode(&self, tagged: bool) -> Result<DecodedCose, CoseError> {
        use coset::{CborSerializable, TaggedCborSerializable};

        let cose = if tagged {
            CoseSign1::from_tagged_slice(&self.0)?
        } else {
            CoseSign1::from_slice(&self.0)?
        };

        Ok(DecodedCose {
            signing_bytes: DecodedUnsignedCose {
                unsigned: CoseUnsigned1 {
                    protected: cose.protected,
                    unprotected: cose.unprotected,
                    payload: cose.payload.unwrap_or_default(),
                },
                payload: (),
            },
            signature: CoseSignatureBytes(cose.signature),
        })
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

pub struct CompactCoseSign1Buf(Vec<u8>);

impl CompactCoseSign1Buf {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
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

pub struct DecodedCose<T = ()> {
    pub signing_bytes: DecodedUnsignedCose<T>,
    pub signature: CoseSignatureBytes,
}

impl<T> DecodedCose<T> {
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> DecodedCose<U> {
        DecodedCose {
            signing_bytes: self.signing_bytes.map(f),
            signature: self.signature,
        }
    }

    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T, &[u8]) -> Result<U, E>,
    ) -> Result<DecodedCose<U>, E> {
        Ok(DecodedCose {
            signing_bytes: self.signing_bytes.try_map(f)?,
            signature: self.signature,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct CoseUnsigned1 {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Vec<u8>,
}

impl CoseUnsigned1 {
    pub fn tbs_data(&self, aad: &[u8]) -> Vec<u8> {
        sig_structure_data(
            coset::SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            &self.payload,
        )
    }
}

/// JWS decoded signing bytes.
#[derive(Clone, PartialEq)]
pub struct DecodedUnsignedCose<T = ()> {
    /// Unsigned.
    pub unsigned: CoseUnsigned1,

    /// Decoded payload.
    pub payload: T,
}

impl<T> DecodedUnsignedCose<T> {
    pub fn map<U>(self, f: impl FnOnce(T, &[u8]) -> U) -> DecodedUnsignedCose<U> {
        let payload = f(self.payload, &self.unsigned.payload);
        DecodedUnsignedCose {
            unsigned: self.unsigned,
            payload,
        }
    }

    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T, &[u8]) -> Result<U, E>,
    ) -> Result<DecodedUnsignedCose<U>, E> {
        let payload = f(self.payload, &self.unsigned.payload)?;
        Ok(DecodedUnsignedCose {
            unsigned: self.unsigned,
            payload,
        })
    }
}

pub struct CoseSignatureBytes(pub Vec<u8>);

pub trait CosePayload {
    /// `typ` header parameter.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
    fn typ(&self) -> Option<Type> {
        None
    }

    fn content_type(&self) -> Option<ContentType> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]>;

    #[allow(async_fn_in_trait)]
    async fn sign(&self, signer: impl CoseSigner) -> Result<CompactCoseSign1Buf, SignatureError> {
        signer.sign(self, None).await
    }
}

pub const TYP_LABEL: Label = Label::Int(16);

pub enum Type {
    UInt(u64),
    Text(String),
}

impl From<Type> for CborValue {
    fn from(ty: Type) -> Self {
        match ty {
            Type::UInt(i) => Self::Integer(i.into()),
            Type::Text(t) => Self::Text(t),
        }
    }
}
