use crate::{
    suite::{AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, ProofConfigurationRef,
};
use pin_project::pin_project;
use ssi_core::futures::FailibleFuture;
use ssi_crypto::{MessageSigner, SignerAdapter};
use ssi_verification_methods::{
    AnyMethod, AnyMethodRef, SignatureAlgorithm, SignatureError, VerificationError,
};
use std::future::Future;
use std::pin::Pin;
use std::task;

mod protocol;
pub use protocol::AnySignatureProtocol;

type SuiteMethod<S> = <S as CryptographicSuite>::VerificationMethod;
type SuiteSign<'a, S, T> = <<S as CryptographicSuite>::SignatureAlgorithm as SignatureAlgorithm<
    SuiteMethod<S>,
>>::Sign<'a, T>;

macro_rules! crypto_suites {
    {
        $(
            $(#[doc = $doc:literal])*
            $(#[cfg($($t:tt)*)])?
            $field_name:ident: $name:ident
        ),*
    } => {
        /// Built-in Data Integrity cryptographic suites.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Suite {
            $(
                $(#[doc = $doc])*
                $(#[cfg($($t)*)])?
                $name
            ),*
        }

        /// Options for all cryptographic suites.
        #[derive(Default, Clone)]
        pub struct Options {
            $(
                $(#[cfg($($t)*)])?
                pub $field_name: <super::$name as $crate::CryptographicSuite>::Options
            ),*
        }

        pub enum AnySignatureAlgorithm {
            $(
                $(#[cfg($($t)*)])?
                $name(<super::$name as $crate::CryptographicSuite>::SignatureAlgorithm)
            ),*
        }

        #[pin_project(project = SignProj)]
        pub enum Sign<'a, S: 'a + MessageSigner<AnySignatureProtocol>> {
            $(
                $(#[cfg($($t)*)])?
                $name(#[pin] SuiteSign<'a, super::$name, SignerAdapter<S, AnySignatureProtocol>>)
            ),*
        }

        impl<'a, S: 'a + MessageSigner<AnySignatureProtocol>> Future for Sign<'a, S> {
            type Output = Result<AnySignature, SignatureError>;

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
                match self.project() {
                    $(
                        $(#[cfg($($t)*)])?
                        SignProj::$name(s) => {
                            s.poll(cx).map_ok(Into::into)
                        }
                    ),*
                }
            }
        }

        impl SignatureAlgorithm<AnyMethod> for AnySignatureAlgorithm {
            type Signature = AnySignature;

            type Protocol = AnySignatureProtocol;

            type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> = FailibleFuture<Sign<'a, S>, SignatureError>;

            fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
                &self,
                method: AnyMethodRef,
                bytes: &'a [u8],
                signer: S
            ) -> Self::Sign<'a, S> {
                match self {
                    $(
                        Self::$name(a) => {
                            match method.try_into() {
                                Ok(method) => {
                                    FailibleFuture::ok(Sign::$name(a.sign(
                                        method,
                                        bytes,
                                        SignerAdapter::new(signer)
                                    )))
                                }
                                Err(e) => {
                                    FailibleFuture::err(e.into())
                                }
                            }
                        }
                    ),*
                }
            }

            fn verify(
                &self,
                signature: AnySignatureRef,
                method: AnyMethodRef,
                bytes: &[u8]
            ) -> Result<bool, VerificationError> {
                match self {
                    $(
                        Self::$name(a) => {
                            a.verify(
                                signature.try_into()?,
                                method.try_into()?,
                                bytes
                            )
                        }
                    ),*
                }
            }
        }

        // #[async_trait::async_trait]
        impl CryptographicSuite for Suite {
            type Transformed = String;
            type Hashed = [u8; 64];

            type VerificationMethod = AnyMethod;

            type Signature = AnySignature;

            type SignatureProtocol = AnySignatureProtocol;

            type SignatureAlgorithm = AnySignatureAlgorithm;

            type Options = Options;

            fn iri(&self) -> &iref::Iri {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => super::$name.iri()
                    ),*
                }
            }

            fn cryptographic_suite(&self) -> Option<&str> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => super::$name.cryptographic_suite()
                    ),*
                }
            }

            fn hash(&self, data: String, proof_configuration: ProofConfigurationRef<Self::VerificationMethod>) -> Result<Self::Hashed, HashError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            super::$name.hash(
                                data,
                                proof_configuration
                                    .try_cast_verification_method()
                                    .map_err(|_| HashError::InvalidVerificationMethod)?
                            )
                        }
                    ),*
                }
            }

            fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
                match self {
                    $(
                        Self::$name => AnySignatureAlgorithm::$name(super::$name.setup_signature_algorithm())
                    ),*
                }
            }
        }
    };
}

crypto_suites! {
    /// W3C RSA Signature Suite 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-rsa2018/>
    #[cfg(all(feature = "w3c", feature = "rsa"))]
    rsa_signature_2018: RsaSignature2018,

    /// W3C Ed25519 Signature 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed25519_signature_2018: Ed25519Signature2018,

    /// W3C Ed25519 Signature 2020.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed25519_signature_2020: Ed25519Signature2020,

    /// W3C EdDSA Cryptosuite v2022.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed_dsa_2022: EdDsa2022,

    /// W3C Ecdsa Secp256k1 Signature 2019.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
    #[cfg(all(feature = "w3c", feature = "secp256k1"))]
    ecdsa_secp_256k1_signature2019: EcdsaSecp256k1Signature2019,

    /// W3C Ecdsa Secp256r1 Signature 2019.
    ///
    /// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
    #[cfg(all(feature = "w3c", feature = "secp256r1"))]
    ecdsa_secp_256r1_signature2019: EcdsaSecp256r1Signature2019,

    /// W3C JSON Web Signature 2020.
    ///
    /// See: <https://w3c-ccg.github.io/lds-jws2020/>
    #[cfg(feature = "w3c")]
    json_web_signature_2020: JsonWebSignature2020
}

// /// Built-in Data Integrity cryptographic suites types.
// pub enum SuiteType {
//     /// W3C RSA Signature Suite 2018.
//     ///
//     /// See: <https://w3c-ccg.github.io/lds-rsa2018/>
//     #[cfg(all(feature = "w3c", feature = "rsa"))]
//     RsaSignature2018,

//     /// W3C Ed25519 Signature 2018.
//     ///
//     /// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
//     #[cfg(all(feature = "w3c", feature = "ed25519"))]
//     Ed25519Signature2018,

//     /// W3C Ed25519 Signature 2020.
//     ///
//     /// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
//     #[cfg(all(feature = "w3c", feature = "ed25519"))]
//     Ed25519Signature2020,

//     /// W3C EdDSA Cryptosuite v2022.
//     ///
//     /// See: <https://w3c.github.io/vc-di-eddsa/>
//     #[cfg(all(feature = "w3c", feature = "ed25519"))]
//     EdDsa2022,

//     /// W3C Ecdsa Secp256k1 Signature 2019.
//     ///
//     /// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
//     #[cfg(all(feature = "w3c", feature = "secp256k1"))]
//     EcdsaSecp256k1Signature2019,

//     /// W3C Ecdsa Secp256r1 Signature 2019.
//     ///
//     /// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
//     #[cfg(all(feature = "w3c", feature = "secp256r1"))]
//     EcdsaSecp256r1Signature2019,

//     /// W3C JSON Web Signature 2020.
//     ///
//     /// See: <https://w3c-ccg.github.io/lds-jws2020/>
//     #[cfg(feature = "w3c")]
//     JsonWebSignature2020,

//     /// W3C Ethereum EIP712 Signature 2021.
//     ///
//     /// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
//     #[cfg(all(feature = "w3c", feature = "eip"))]
//     EthereumEip712Signature2021,

//     /// DIF Ecdsa Secp256k1 Recovery Signature 2019.
//     ///
//     /// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
//     #[cfg(all(feature = "dif", feature = "secp256k1"))]
//     EcdsaSecp256k1RecoverySignature2020,

//     /// Unspecified Ethereum Personal Signature 2021.
//     #[cfg(feature = "eip")]
//     EthereumPersonalSignature2021,

//     /// Unspecified Eip712 Signature 2021.
//     #[cfg(feature = "eip")]
//     Eip712Signature2021,

//     /// Unspecified Ed25519 BLAKE2B Digest Size 20 Base58 Check Encoded Signature 2021.
//     #[cfg(feature = "tezos")]
//     Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

//     /// Unspecified P256 BLAKE2B Digest Size 20 Base58 Check Encoded Signature 2021.
//     #[cfg(feature = "tezos")]
//     P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

//     /// Unspecified Tezos Signature 2021.
//     #[cfg(feature = "tezos")]
//     TezosSignature2021,

//     /// Unspecified Tezos Jcs Signature 2021.
//     #[cfg(feature = "tezos")]
//     TezosJcsSignature2021,

//     /// Unspecified Solana Signature 2021.
//     #[cfg(feature = "solana")]
//     SolanaSignature2021,

//     /// Unspecified Aleo Signature 2021.
//     #[cfg(feature = "aleo")]
//     AleoSignature2021,

//     /// Unknown suite type.
//     Unknown(String),
// }
