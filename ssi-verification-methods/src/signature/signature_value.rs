use ssi_crypto::VerificationError;

/// `https://w3id.org/security#signatureValue` signature value, encoded in
/// base64.
pub struct SignatureValueBuf(pub String);

impl SignatureValueBuf {
    pub fn as_signature_value(&self) -> &SignatureValue {
        unsafe { std::mem::transmute(self.0.as_str()) }
    }
}

impl From<String> for SignatureValueBuf {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for SignatureValueBuf {
    type Target = SignatureValue;

    fn deref(&self) -> &Self::Target {
        self.as_signature_value()
    }
}

/// Unsized `https://w3id.org/security#signatureValue` signature value, encoded
/// in base64.
#[repr(transparent)]
pub struct SignatureValue(str);

impl ssi_crypto::Signature for SignatureValueBuf {
    type Reference<'a> = &'a SignatureValue where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self.as_signature_value()
    }
}

impl SignatureValue {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::Base::Base64
            .decode(&self.0)
            .map_err(|_| VerificationError::InvalidProof)
    }
}
