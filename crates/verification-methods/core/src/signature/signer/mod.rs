use ssi_claims_core::{MessageSignatureError, SignatureError};
use ssi_crypto::AlgorithmInstance;
use ssi_jwk::JWK;
use std::borrow::Cow;

pub mod local;
pub use local::LocalSigner;

pub mod single_secret;
pub use single_secret::SingleSecretSigner;

use crate::VerificationMethod;

// /// Verification method signer.
// pub trait Signer<M: VerificationMethod> {
//     type MessageSigner;

//     #[allow(async_fn_in_trait)]
//     async fn for_method(
//         &self,
//         method: Cow<'_, M>,
//     ) -> Result<Option<Self::MessageSigner>, SignatureError>;
// }

// impl<'s, M: VerificationMethod, S: Signer<M>> Signer<M> for &'s S {
//     type MessageSigner = S::MessageSigner;

//     async fn for_method(
//         &self,
//         method: Cow<'_, M>,
//     ) -> Result<Option<Self::MessageSigner>, SignatureError> {
//         S::for_method(*self, method).await
//     }
// }

// pub trait MessageSigner: Sized {
//     #[allow(async_fn_in_trait)]
//     async fn sign(
//         self,
//         algorithm: AlgorithmInstance,
//         message: &[u8],
//     ) -> Result<Vec<u8>, MessageSignatureError>;

//     #[allow(async_fn_in_trait)]
//     async fn sign_multi(
//         self,
//         algorithm: AlgorithmInstance,
//         messages: &[Vec<u8>],
//     ) -> Result<Vec<u8>, MessageSignatureError> {
//         match messages.split_first() {
//             Some((message, [])) => self.sign(algorithm, message).await,
//             // Some(_) => Err(MessageSignatureError::TooManyMessages),
//             Some(_) => todo!(),
//             None => Err(MessageSignatureError::MissingMessage),
//         }
//     }
// }

// impl MessageSigner for JWK {
//     async fn sign(
//         self,
//         algorithm: AlgorithmInstance,
//         message: &[u8],
//     ) -> Result<Vec<u8>, MessageSignatureError> {
//         // ssi_jws::sign_bytes(algorithm.into().try_into()?, message, &self)
//         //     .map_err(MessageSignatureError::signature_failed)
//         todo!()
//     }

//     #[allow(unused_variables)]
//     async fn sign_multi(
//         self,
//         algorithm: AlgorithmInstance,
//         messages: &[Vec<u8>],
//     ) -> Result<Vec<u8>, MessageSignatureError> {
//         // match algorithm.into() {
//         //     #[cfg(feature = "bbs")]
//         //     ssi_crypto::AlgorithmInstance::Bbs(bbs) => {
//         //         let sk: ssi_bbs::BBSplusSecretKey = self
//         //             .try_into()
//         //             .map_err(|_| MessageSignatureError::InvalidSecretKey)?;
//         //         let pk = sk.public_key();
//         //         ssi_bbs::sign(*bbs.0, &sk, &pk, messages)
//         //     }
//         //     other => Err(MessageSignatureError::UnsupportedAlgorithm(
//         //         other.algorithm().to_string(),
//         //     )),
//         // }
//         todo!()
//     }
// }