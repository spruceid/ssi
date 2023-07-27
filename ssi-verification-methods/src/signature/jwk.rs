use ssi_jws::{CompactJWSStr, CompactJWSString};

/// `https://w3id.org/security#jwk` signature value, encoded as a JWK.
pub struct Jws(pub CompactJWSString);

impl ssi_crypto::Signature for Jws {
    type Reference<'a> = &'a CompactJWSStr where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        &*self.0
    }
}

impl From<CompactJWSString> for Jws {
    fn from(value: CompactJWSString) -> Self {
        Self(value)
    }
}
