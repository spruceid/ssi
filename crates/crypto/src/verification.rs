use crate::{key::KeyMetadata, AlgorithmInstance, Error, Options};

pub trait Verifier {
    type VerifyingKey: VerifyingKey;

    #[allow(async_fn_in_trait)]
    async fn get_verifying_key_with(
        &self,
        id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Option<Self::VerifyingKey>, Error>;

    #[allow(async_fn_in_trait)]
    async fn get_verifying_key(
        &self,
        id: Option<&[u8]>,
    ) -> Result<Option<Self::VerifyingKey>, Error> {
        let options = Options::default();
        self.get_verifying_key_with(id, &options).await
    }

    #[allow(async_fn_in_trait)]
    async fn require_verifying_key_with(
        &self,
        id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Self::VerifyingKey, Error> {
        self.get_verifying_key_with(id, options)
            .await?
            .ok_or_else(|| Error::KeyNotFound(id.map(|id| id.to_vec())))
    }

    #[allow(async_fn_in_trait)]
    async fn require_verifying_key(&self, id: Option<&[u8]>) -> Result<Self::VerifyingKey, Error> {
        let options = Options::default();
        self.require_verifying_key_with(id, &options).await
    }

    #[allow(async_fn_in_trait)]
    async fn verify_with(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        options: &Options,
    ) -> Result<SignatureVerification, Error> {
        let key = self.require_verifying_key_with(key_id, options).await?;
        let (_, algorithm) = key.key_metadata().into_id_and_algorithm(algorithm)?;
        key.verify_message(algorithm, signing_bytes, signature)
    }

    #[allow(async_fn_in_trait)]
    async fn verify(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        let options = Options::default();
        self.verify_with(key_id, algorithm, signing_bytes, signature, &options)
            .await
    }
}

impl<T: Verifier> Verifier for &T {
    type VerifyingKey = T::VerifyingKey;

    async fn get_verifying_key_with(
        &self,
        key_id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Option<Self::VerifyingKey>, Error> {
        T::get_verifying_key_with(self, key_id, options).await
    }

    async fn verify_with(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        options: &Options,
    ) -> Result<SignatureVerification, Error> {
        T::verify_with(*self, key_id, algorithm, signing_bytes, signature, options).await
    }
}

pub trait VerifyingKey {
    fn key_metadata(&self) -> KeyMetadata;

    fn verify_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error>;
}

pub type SignatureVerification = Result<(), RejectedSignature>;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RejectedSignature {
    #[error("missing signature")]
    Missing,

    #[error("signature mismatch")]
    Mismatch,
}
