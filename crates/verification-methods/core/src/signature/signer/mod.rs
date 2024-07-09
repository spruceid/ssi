use ssi_claims_core::{MessageSignatureError, SignatureError};
use ssi_crypto::algorithm::SignatureAlgorithmType;
use ssi_jwk::JWK;
use std::{borrow::Cow, marker::PhantomData};

pub mod local;
pub use local::LocalSigner;

pub mod single_secret;
pub use single_secret::SingleSecretSigner;

use crate::VerificationMethod;

/// Verification method signer.
pub trait Signer<M: VerificationMethod> {
    type MessageSigner;

    #[allow(async_fn_in_trait)]
    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError>;
}

impl<'s, M: VerificationMethod, S: Signer<M>> Signer<M> for &'s S {
    type MessageSigner = S::MessageSigner;

    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        S::for_method(*self, method).await
    }
}

pub trait MessageSigner<A: SignatureAlgorithmType>: Sized {
    #[allow(async_fn_in_trait)]
    async fn sign(
        self,
        algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign_multi(
        self,
        algorithm: A::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match messages.split_first() {
            Some((message, [])) => self.sign(algorithm, message).await,
            // Some(_) => Err(MessageSignatureError::TooManyMessages),
            Some(_) => todo!(),
            None => Err(MessageSignatureError::MissingMessage),
        }
    }
}

impl<A: SignatureAlgorithmType> MessageSigner<A> for JWK
where
    A::Instance: Into<ssi_crypto::AlgorithmInstance>,
{
    async fn sign(
        self,
        algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into().try_into()?, message, &self)
            .map_err(MessageSignatureError::signature_failed)
    }

    #[allow(unused_variables)]
    async fn sign_multi(
        self,
        algorithm: <A as SignatureAlgorithmType>::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match algorithm.into() {
            #[cfg(feature = "bbs")]
            ssi_crypto::AlgorithmInstance::Bbs(bbs) => {
                let sk: ssi_bbs::BBSplusSecretKey = self
                    .try_into()
                    .map_err(|_| MessageSignatureError::InvalidSecretKey)?;
                let pk = sk.public_key();
                ssi_bbs::sign(*bbs.0, &sk, &pk, messages)
            }
            other => Err(MessageSignatureError::UnsupportedAlgorithm(
                other.algorithm().to_string(),
            )),
        }
    }
}

pub struct MessageSignerAdapter<S, A> {
    // Underlying signer.
    signer: S,

    algorithm: PhantomData<A>,
}

impl<S, A> MessageSignerAdapter<S, A> {
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            algorithm: PhantomData,
        }
    }
}

impl<S: MessageSigner<A>, A: SignatureAlgorithmType, B: SignatureAlgorithmType> MessageSigner<B>
    for MessageSignerAdapter<S, A>
where
    A::Instance: TryFrom<B::Instance>,
{
    async fn sign(
        self,
        algorithm: B::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)?;

        self.signer.sign(algorithm, message).await
    }

    async fn sign_multi(
        self,
        algorithm: <B as SignatureAlgorithmType>::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)?;

        self.signer.sign_multi(algorithm, messages).await
    }
}
