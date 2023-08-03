use ssi_crypto::VerificationError;
use ssi_jwk::JWK;
use ssi_jws::CompactJWSStr;

use super::{Jws, SignatureValue, SignatureValueBuf};

/// Any signature.
pub struct Any {
    /// Signature value.
    pub value: Value,

    /// Public key.
    pub public_key: Option<PublicKey>
}

impl ssi_crypto::Referencable for Any {
    type Reference<'a> = AnyRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnyRef {
            value: self.value.as_reference(),
            public_key: self.public_key.as_ref().map(PublicKey::as_reference)
        }
    }
}

/// Any signature value.
///
/// Modern cryptographic suites use the <https://w3id.org/security#proofValue>
/// property to provide the proof value using a multibase encoding.
/// However older cryptographic suites like `Ed25519Signature2018` may use
/// different encoding, like [Detached Json Web Signatures][1].
///
/// [1]: <https://tools.ietf.org/html/rfc7797>
pub enum Value {
    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#jws> property.
    ///
    /// See: <https://tools.ietf.org/html/rfc7797>
    Jws(Jws),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#signatureValue> property.
    SignatureValue(SignatureValueBuf),

    /// Arbitrary value using the
    /// <https://w3id.org/security#proofValue> property.
    ///
    /// This this the official way of providing the proof value, but some older
    /// cryptographic suites like `Ed25519Signature2018` may use different
    /// means.
    ProofValue(String)
}

impl Value {
    pub fn as_proof_value(&self) -> Option<&str> {
        match self {
            Self::ProofValue(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_jws(&self) -> Option<&ssi_jws::CompactJWSStr> {
        match self {
            Self::Jws(jws) => Some(&jws.0),
            _ => None,
        }
    }

    pub fn as_base64(&self) -> Option<&SignatureValue> {
        match self {
            Self::SignatureValue(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_proof_value(self) -> Option<String> {
        match self {
            Self::ProofValue(m) => Some(m),
            _ => None,
        }
    }

    pub fn into_jws(self) -> Option<ssi_jws::CompactJWSString> {
        match self {
            Self::Jws(jws) => Some(jws.0),
            _ => None,
        }
    }

    pub fn into_base64(self) -> Option<String> {
        match self {
            Self::SignatureValue(value) => Some(value.0),
            _ => None,
        }
    }
}

impl ssi_crypto::Referencable for Value {
    type Reference<'a> = ValueRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        match self {
            Self::Jws(j) => ValueRef::Jws(j.as_reference()),
            Self::ProofValue(v) => ValueRef::ProofValue(v),
            Self::SignatureValue(s) => ValueRef::SignatureValue(s.as_reference())
        }
    }
}

/// Any public key that might be included alongside the signature.
pub enum PublicKey {
    Jwk(Box<JWK>),
    Multibase(ssi_security::layout::Multibase)
}

impl ssi_crypto::Referencable for PublicKey {
    type Reference<'a> = PublicKeyRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        match self {
            Self::Jwk(j) => PublicKeyRef::Jwk(j),
            Self::Multibase(m) => PublicKeyRef::Multibase(m)
        }
    }
}

/// Any signature.
pub struct AnyRef<'a> {
    /// Signature value.
    pub value: ValueRef<'a>,

    /// Public key.
    pub public_key: Option<PublicKeyRef<'a>>
}

impl<'a> TryFrom<AnyRef<'a>> for &'a str {
    type Error = VerificationError;

    fn try_from(value: AnyRef<'a>) -> Result<Self, Self::Error> {
        match value.value {
            super::any::ValueRef::ProofValue(v) => Ok(v),
            _ => Err(VerificationError::InvalidSignature)
        }
    }
}

/// Any signature value.
///
/// Modern cryptographic suites use the <https://w3id.org/security#proofValue>
/// property to provide the proof value using a multibase encoding.
/// However older cryptographic suites like `Ed25519Signature2018` may use
/// different encoding, like [Detached Json Web Signatures][1].
///
/// [1]: <https://tools.ietf.org/html/rfc7797>
pub enum ValueRef<'a> {
    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#jws> property.
    ///
    /// See: <https://tools.ietf.org/html/rfc7797>
    Jws(&'a CompactJWSStr),

    /// Detached Json Web Signature using the deprecated
    /// <https://w3id.org/security#signatureValue> property.
    SignatureValue(&'a SignatureValue),

    /// Arbitrary value using the
    /// <https://w3id.org/security#proofValue> property.
    ///
    /// This this the official way of providing the proof value, but some older
    /// cryptographic suites like `Ed25519Signature2018` may use different
    /// means.
    ProofValue(&'a str)
}

impl<'a> ValueRef<'a> {
    pub fn as_proof_value(self) -> Option<&'a str> {
        match self {
            Self::ProofValue(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_jws(self) -> Option<&'a ssi_jws::CompactJWSStr> {
        match self {
            Self::Jws(jws) => Some(jws),
            _ => None,
        }
    }

    pub fn as_base64(self) -> Option<&'a SignatureValue> {
        match self {
            Self::SignatureValue(value) => Some(value),
            _ => None,
        }
    }
}


/// Any public key that might be included alongside the signature.
pub enum PublicKeyRef<'a> {
    Jwk(&'a JWK),
    Multibase(&'a ssi_security::layout::Multibase)
}