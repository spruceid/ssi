use std::borrow::Cow;

use ssi_claims_core::{MessageSignatureError, SignatureError};
use ssi_crypto::algorithm::SignatureAlgorithmType;
use ssi_verification_methods::{protocol::WithProtocol, VerificationMethod};

use crate::AnyProtocol;

pub struct AnySigner<S>(pub S);

impl<M, S> ssi_verification_methods::Signer<M> for AnySigner<S>
where
    M: VerificationMethod + Into<ssi_verification_methods::AnyMethod>,
    S: ssi_verification_methods::Signer<ssi_verification_methods::AnyMethod>,
{
    type MessageSigner = AnyMessageSigner<S::MessageSigner>;

    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        let any_method = method.into_owned().into();
        Ok(self
            .0
            .for_method(Cow::Owned(any_method))
            .await?
            .map(AnyMessageSigner))
    }
}

pub struct AnyMessageSigner<S>(pub S);

impl<S, A: SignatureAlgorithmType> ssi_verification_methods::MessageSigner<A>
    for AnyMessageSigner<S>
where
    S: ssi_verification_methods::MessageSigner<AnySignatureAlgorithm>,
    A::Instance: IntoAnySignatureAlgorithm,
{
    async fn sign(
        self,
        algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        self.0
            .sign(algorithm.into_any_signature_algorithm(), message)
            .await
    }

    async fn sign_multi(
        self,
        algorithm: <A as SignatureAlgorithmType>::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        self.0
            .sign_multi(algorithm.into_any_signature_algorithm(), messages)
            .await
    }
}

pub type AnySignatureAlgorithm = WithProtocol<ssi_crypto::Algorithm, AnyProtocol>;

pub type AnySignatureAlgorithmInstance = WithProtocol<ssi_crypto::AlgorithmInstance, AnyProtocol>;

pub trait IntoAnySignatureAlgorithm {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance;
}

impl IntoAnySignatureAlgorithm for ssi_jwk::Algorithm {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::AlgorithmInstance {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self, AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::RS256 {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::ES256 {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::ES256K {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::ES256KR {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::AnyESKeccakK {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::EdDSA {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::EdBlake2b {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::ESBlake2b {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::ES256OrES384 {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
impl IntoAnySignatureAlgorithm for ssi_crypto::algorithm::BbsInstance {
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.into(), AnyProtocol::None)
    }
}

#[cfg(feature = "tezos")]
impl IntoAnySignatureAlgorithm
    for WithProtocol<ssi_crypto::algorithm::AnyBlake2b, ssi_data_integrity_suites::TezosWallet>
{
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.0.into(), self.1.into())
    }
}

impl IntoAnySignatureAlgorithm
    for WithProtocol<
        ssi_crypto::algorithm::AnyESKeccakK,
        ssi_verification_methods::protocol::EthereumWallet,
    >
{
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.0.into(), self.1.into())
    }
}

#[cfg(feature = "solana")]
impl IntoAnySignatureAlgorithm
    for WithProtocol<ssi_jwk::Algorithm, ssi_verification_methods::protocol::Base58Btc>
{
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.0.into(), self.1.into())
    }
}

#[cfg(feature = "aleo")]
impl IntoAnySignatureAlgorithm
    for WithProtocol<ssi_jwk::Algorithm, ssi_verification_methods::protocol::Base58BtcMultibase>
{
    fn into_any_signature_algorithm(self) -> AnySignatureAlgorithmInstance {
        WithProtocol(self.0.into(), self.1.into())
    }
}
