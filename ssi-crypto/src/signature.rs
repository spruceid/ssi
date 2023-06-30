#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("unknown verification method")]
    UnknownVerificationMethod,
}

pub trait Signer<M> {
    fn sign(&self, method: &M, bytes: &[u8]) -> Result<Vec<u8>, SignatureError>;
}
