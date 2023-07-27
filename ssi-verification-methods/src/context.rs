use ssi_crypto::VerificationError;
use ssi_jwk::JWK;

/// Verification method context error.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// The verification method requires the cryptographic suite to provide the
    /// public key, but it is missing.
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<ContextError> for VerificationError {
    fn from(value: ContextError) -> Self {
        match value {
            ContextError::MissingPublicKey => Self::MissingPublicKey,
        }
    }
}

/// Empty context, used by most verification methods.
pub type NoContext = ();

/// Verification method context providing a JWK public key.
///
/// The key is provided by the cryptographic suite to the verification method.
#[derive(Debug, Clone, Copy)]
pub struct PublicKeyJwkContext<'a> {
    /// Public key.
    pub public_key_jwk: &'a JWK,
}

impl<'a> PublicKeyJwkContext<'a> {
    pub fn new(public_key_jwk: &'a JWK) -> Self {
        Self { public_key_jwk }
    }
}

impl<'a> From<&'a JWK> for PublicKeyJwkContext<'a> {
    fn from(value: &'a JWK) -> Self {
        PublicKeyJwkContext {
            public_key_jwk: value,
        }
    }
}

/// Any context, compatible with all verification methods, but faillible.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnyContext<'a> {
    /// Public key, required by some verification methods.
    pub public_key_jwk: Option<&'a JWK>,
}

impl<'a> From<PublicKeyJwkContext<'a>> for AnyContext<'a> {
    fn from(value: PublicKeyJwkContext<'a>) -> Self {
        Self {
            public_key_jwk: Some(value.public_key_jwk),
        }
    }
}

impl<'a> TryFrom<AnyContext<'a>> for PublicKeyJwkContext<'a> {
    type Error = ContextError;

    fn try_from(value: AnyContext<'a>) -> Result<Self, Self::Error> {
        match value.public_key_jwk {
            Some(jwk) => Ok(PublicKeyJwkContext {
                public_key_jwk: jwk,
            }),
            None => Err(ContextError::MissingPublicKey),
        }
    }
}

impl<'a> From<NoContext> for AnyContext<'a> {
    fn from(_value: NoContext) -> Self {
        Self::default()
    }
}

impl<'a> From<AnyContext<'a>> for NoContext {
    fn from(_value: AnyContext<'a>) -> Self {}
}
