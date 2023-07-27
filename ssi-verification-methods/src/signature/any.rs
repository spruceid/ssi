use crate::signature_union;

use super::{Jws, ProofValue, SignatureValue, SignatureValueBuf};

signature_union! {
    /// Any signature value.
    ///
    /// Modern cryptographic suites use the <https://w3id.org/security#proofValue>
    /// property to provide the proof value using a multibase encoding.
    /// However older cryptographic suites like `Ed25519Signature2018` may use
    /// different encoding, like [Detached Json Web Signatures][1].
    ///
    /// [1]: <https://tools.ietf.org/html/rfc7797>
    pub enum Any, AnyRef {
        /// Detached Json Web Signature using the deprecated
        /// <https://w3id.org/security#jws> property.
        ///
        /// See: <https://tools.ietf.org/html/rfc7797>
        Jws(Jws),

        /// Detached Json Web Signature using the deprecated
        /// <https://w3id.org/security#signatureValue> property.
        SignatureValue(SignatureValueBuf),

        /// Standard multibase encoding using the
        /// <https://w3id.org/security#proofValue> property.
        ///
        /// This this the official way of providing the proof value, but some older
        /// cryptographic suites like `Ed25519Signature2018` may use different
        /// means.
        ProofValue(ProofValue)
    }
}

impl Any {
    pub fn as_multibase(&self) -> Option<&ssi_security::layout::Multibase> {
        match self {
            Self::ProofValue(m) => Some(&m.0),
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

    pub fn into_multibase(self) -> Option<ssi_security::layout::Multibase> {
        match self {
            Self::ProofValue(m) => Some(m.0),
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

impl<'a> AnyRef<'a> {
    pub fn as_multibase(self) -> Option<&'a ssi_security::layout::Multibase> {
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
