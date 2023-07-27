/// `https://w3id.org/security#proofValue` signature value, multibase-encoded.
pub struct ProofValue(pub ssi_security::layout::Multibase);

impl ssi_crypto::Signature for ProofValue {
    type Reference<'a> = &'a ssi_security::layout::Multibase where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        &self.0
    }
}

impl From<ssi_security::layout::Multibase> for ProofValue {
    fn from(value: ssi_security::layout::Multibase) -> Self {
        Self(value)
    }
}
