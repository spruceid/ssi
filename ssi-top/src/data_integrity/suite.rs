use linked_data::LinkedData;
use pin_project::pin_project;
use ssi_core::futures::FailibleFuture;
use ssi_crypto::{MessageSignatureError, MessageSigner, SignerAdapter};
use ssi_jwk::JWK;
use ssi_vc_ldp::{
    suite::{AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, CryptographicSuiteInput, LinkedDataInput, ProofConfigurationRef,
};
use ssi_verification_methods::{
    covariance_rule, Referencable, ReferenceOrOwned, ReferenceOrOwnedRef, SignatureAlgorithm,
    SignatureError, SigningMethod, VerificationError,
};
use std::future::Future;
use std::pin::Pin;
use std::task;

use crate::{AnyMethod, AnyMethodRef, AnyProtocolOutput, AnySignatureProtocol};

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
        pub enum AnySuite {
            $(
                $(#[doc = $doc])*
                $(#[cfg($($t)*)])?
                $name
            ),*
        }

        pub enum AnySignatureAlgorithm {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_vc_ldp::suite::$name as ssi_vc_ldp::CryptographicSuite>::SignatureAlgorithm)
            ),*
        }

        #[pin_project(project = SignProj)]
        pub enum Sign<'a, S: 'a + MessageSigner<AnySignatureProtocol>> {
            $(
                $(#[cfg($($t)*)])?
                $name(#[pin] SuiteSign<'a, ssi_vc_ldp::suite::$name, SignerAdapter<S, AnySignatureProtocol>>)
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
            type Options = AnySuiteOptions;

            type Signature = AnySignature;

            type Protocol = AnySignatureProtocol;

            type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> = FailibleFuture<Sign<'a, S>, SignatureError>;

            fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
                &self,
                options: <Self::Options as Referencable>::Reference<'a>,
                method: AnyMethodRef,
                bytes: &'a [u8],
                signer: S
            ) -> Self::Sign<'a, S> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(a) => {
                            match method.try_into() {
                                Ok(method) => {
                                    match options.try_into() {
                                        Ok(options) => {
                                            FailibleFuture::ok(Sign::$name(a.sign(
                                                options,
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
                options: AnySuiteOptionsRef,
                signature: AnySignatureRef,
                method: AnyMethodRef,
                bytes: &[u8]
            ) -> Result<bool, VerificationError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(a) => {
                            a.verify(
                                options.try_into()?,
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
        impl CryptographicSuite for AnySuite {
            type Transformed = String;
            type Hashed = [u8; 64];

            type VerificationMethod = AnyMethod;

            type Signature = AnySignature;

            type SignatureProtocol = AnySignatureProtocol;

            type SignatureAlgorithm = AnySignatureAlgorithm;

            type Options = AnySuiteOptions;

            fn iri(&self) -> &iref::Iri {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_vc_ldp::suite::$name.iri()
                    ),*
                }
            }

            fn cryptographic_suite(&self) -> Option<&str> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_vc_ldp::suite::$name.cryptographic_suite()
                    ),*
                }
            }

            fn hash(&self, data: String, proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>) -> Result<Self::Hashed, HashError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            ssi_vc_ldp::suite::$name.hash(
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
                        $(#[cfg($($t)*)])?
                        Self::$name => AnySignatureAlgorithm::$name(ssi_vc_ldp::suite::$name.setup_signature_algorithm())
                    ),*
                }
            }
        }
    };
}

/// Options for all cryptographic suites.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct AnySuiteOptions {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Box<JWK>,
}

impl AnySuiteOptions {
    pub fn new(public_key_jwk: JWK) -> Self {
        Self {
            public_key_jwk: Box::new(public_key_jwk),
        }
    }
}

impl Referencable for AnySuiteOptions {
    type Reference<'a> = AnySuiteOptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySuiteOptionsRef {
            public_key_jwk: &self.public_key_jwk,
        }
    }

    covariance_rule!();
}

#[derive(Clone, Copy)]
pub struct AnySuiteOptionsRef<'a> {
    pub public_key_jwk: &'a JWK,
}

impl<'a> From<AnySuiteOptionsRef<'a>> for () {
    fn from(_value: AnySuiteOptionsRef<'a>) -> Self {
        ()
    }
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
    json_web_signature_2020: JsonWebSignature2020,

    /// DIF Ecdsa Secp256k1 Recovery Signature 2020.
    ///
    /// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
    #[cfg(all(feature = "dif", feature = "secp256k1"))]
    ecdsa_secp256k1_recovery_signature2020: EcdsaSecp256k1RecoverySignature2020,

    /// Unspecified Solana Signature 2021.
    #[cfg(feature = "solana")]
    solana_signature_2021: SolanaSignature2021,

    /// Unspecified Aleo Signature 2021.
    #[cfg(feature = "aleo")]
    aleo_signature_2021: AleoSignature2021
}

impl AnySuite {
    pub fn pick(
        jwk: &JWK,
        verification_method: Option<&ReferenceOrOwned<AnyMethod>>,
    ) -> Option<Self> {
        use ssi_jwk::Algorithm;
        let algorithm = jwk.get_algorithm()?;
        Some(match algorithm {
            #[cfg(feature = "rsa")]
            Algorithm::RS256 => Self::RsaSignature2018,
            #[cfg(feature = "w3c")]
            Algorithm::PS256 => Self::JsonWebSignature2020,
            #[cfg(feature = "w3c")]
            Algorithm::ES384 => Self::JsonWebSignature2020,
            #[cfg(feature = "aleo")]
            Algorithm::AleoTestnet1Signature => Self::AleoSignature2021,
            Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
                #[cfg(feature = "solana")]
                Some(vm)
                    if (vm.id().starts_with("did:sol:") || vm.id().starts_with("did:pkh:sol:"))
                        && vm.id().ends_with("#SolanaMethod2021") =>
                {
                    Self::SolanaSignature2021
                }
                #[cfg(feature = "tezos")]
                Some(URI::String(ref vm))
                    if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
                {
                    if vm.ends_with("#TezosMethod2021") {
                        Self::TezosSignature2021
                    } else {
                        Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    }
                }
                #[cfg(feature = "ed25519")]
                _ => Self::Ed25519Signature2018,
                #[cfg(not(feature = "ed25519"))]
                _ => {
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                        "ed25519 or tezos or solana",
                    )))
                }
            },
            Algorithm::ES256 | Algorithm::ESBlake2b => match verification_method {
                #[cfg(feature = "tezos")]
                Some(URI::String(ref vm))
                    if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
                {
                    if vm.ends_with("#TezosMethod2021") {
                        Self::TezosSignature2021
                    } else {
                        Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    }
                }
                #[cfg(feature = "secp256r1")]
                _ => Self::EcdsaSecp256r1Signature2019,
                #[cfg(not(feature = "secp256r1"))]
                _ => {
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                        "secp256r1 or tezos",
                    )))
                }
            },
            Algorithm::ES256K | Algorithm::ESBlake2bK => match verification_method {
                #[cfg(any(feature = "tezos", feature = "dif"))]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    #[cfg(feature = "tezos")]
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Ok(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "dif")]
                    return Ok(Self::EcdsaSecp256k1RecoverySignature2020);

                    #[cfg(not(feature = "dif"))]
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures("dif or tezos")));
                }
                #[cfg(feature = "secp256k1")]
                _ => Self::EcdsaSecp256k1Signature2019,

                #[allow(unreachable_patterns)]
                _ => return None,
            },
            Algorithm::ES256KR => {
                // #[allow(clippy::if_same_then_else)]
                #[cfg(feature = "eip")]
                if use_eip712sig(jwk) {
                    return Ok(Self::EthereumEip712Signature2021);
                }
                #[cfg(feature = "eip")]
                if use_epsig(jwk) {
                    return Ok(Self::EthereumPersonalSignature2021);
                }
                match verification_method {
                    #[cfg(feature = "eip")]
                    Some(vm)
                        if (vm.id().starts_with("did:ethr:")
                            || vm.id().starts_with("did:pkh:eth:"))
                            && vm.id().ends_with("#Eip712Method2021") =>
                    {
                        Self::Eip712Signature2021
                    }
                    #[cfg(all(feature = "fip", feature = "secp256k1"))]
                    _ => Self::EcdsaSecp256k1RecoverySignature2020,
                    _ => return None,
                }
            }
            _ => return None,
        })
    }
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

impl<'a, T, V: rdf_types::Vocabulary, I: rdf_types::Interpretation, G>
    CryptographicSuiteInput<T, LinkedDataInput<'a, V, I, G>> for AnySuite
where
    I: rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    G: rdf_types::Generator<()>,
    T: linked_data::LinkedData<V, I>,
{
    fn transform(
        &self,
        data: &T,
        context: LinkedDataInput<'a, V, I, G>,
        params: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, ssi_vc_ldp::suite::TransformError> {
        todo!()
    }
}

impl SigningMethod<JWK, AnySignatureProtocol> for AnyMethod {
    fn sign_ref(
        this: AnyMethodRef,
        secret: &JWK,
        protocol: AnySignatureProtocol,
        bytes: &[u8],
    ) -> Result<AnyProtocolOutput, MessageSignatureError> {
        todo!()
    }
}
