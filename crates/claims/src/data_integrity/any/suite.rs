use linked_data::{LinkedDataDeserializePredicateObjects, LinkedDataDeserializeSubject};
use rdf_types::{interpretation::ReverseIriInterpretation, Interpretation, Vocabulary};
use ssi_core::Referencable;
use ssi_crypto::{MessageSignatureError, MessageSigner, SignerAdapter};
use ssi_jwk::JWK;
use ssi_vc_data_integrity::{
    suite::{AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, ProofConfigurationRef,
};
use ssi_verification_methods::{
    ReferenceOrOwned, SignatureAlgorithm, SignatureError, SigningMethod, VerificationError,
};

use super::{AnySuiteOptions, AnySuiteOptionsRef, Transformed};
use crate::{AnyMethod, AnyMethodRef, AnySignatureProtocol};

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializePredicateObjects<I, V> for AnySuite
where
    I: ReverseIriInterpretation<Iri = V::Iri>,
{
    fn deserialize_objects_in<'a, D>(
        vocabulary: &V,
        interpretation: &I,
        dataset: &D,
        graph: &D::Graph,
        objects: impl IntoIterator<Item = &'a I::Resource>,
        context: linked_data::Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        I::Resource: 'a,
        D: linked_data::grdf::Dataset<
            Subject = I::Resource,
            Predicate = I::Resource,
            Object = I::Resource,
            GraphLabel = I::Resource,
        >,
    {
        let mut objects = objects.into_iter();
        match objects.next() {
            Some(object) => match objects.next() {
                Some(_) => Err(linked_data::FromLinkedDataError::TooManyValues(
                    context.into_iris(vocabulary, interpretation),
                )),
                None => {
                    Self::deserialize_subject(vocabulary, interpretation, dataset, graph, object)
                }
            },
            None => Err(linked_data::FromLinkedDataError::MissingRequiredValue(
                context.into_iris(vocabulary, interpretation),
            )),
        }
    }
}

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

        impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializeSubject<I, V> for AnySuite
        where
            I: ReverseIriInterpretation<Iri = V::Iri>
        {
            fn deserialize_subject_in<D>(
                vocabulary: &V,
                interpretation: &I,
                _dataset: &D,
                _graph: &D::Graph,
                resource: &I::Resource,
                context: linked_data::Context<I>
            ) -> Result<Self, linked_data::FromLinkedDataError>
            where
                D: linked_data::grdf::Dataset<
                    Subject = I::Resource,
                    Predicate = I::Resource,
                    Object = I::Resource,
                    GraphLabel = I::Resource,
                >
            {
                let mut known_iri = None;

                for i in interpretation.iris_of(resource) {
                    let iri = vocabulary.iri(i).unwrap();
                    known_iri = Some(iri);
                    $(
                        $(#[cfg($($t)*)])?
                        if iri == ssi_vc_data_integrity::suite::$name::IRI {
                            eprintln!("MATCHING: {iri} as `{}`", stringify!($name));
                            return Ok(Self::$name)
                        }
                    )*
                }

                match known_iri {
                    Some(iri) => {
                        Err(linked_data::FromLinkedDataError::UnsupportedIri {
                            context: context.into_iris(vocabulary, interpretation),
                            found: iri.to_owned(),
                            supported: Some(vec![
                                $(
                                    $(#[cfg($($t)*)])?
                                    ssi_vc_data_integrity::suite::$name::IRI.to_owned(),
                                )*
                            ])
                        })
                    }
                    None => {
                        Err(linked_data::FromLinkedDataError::ExpectedIri(
                            context.into_iris(vocabulary, interpretation)
                        ))
                    }
                }
            }
        }

        pub enum AnySignatureAlgorithm {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_vc_data_integrity::suite::$name as ssi_vc_data_integrity::CryptographicSuite>::SignatureAlgorithm)
            ),*
        }

        // #[pin_project(project = SignProj)]
        // pub enum Sign<'a, S: 'a + MessageSigner<ssi_jwk::Algorithm, AnySignatureProtocol>> {
        //     $(
        //         $(#[cfg($($t)*)])?
        //         $name(#[pin] SuiteSign<'a, ssi_vc_data_integrity::suite::$name, SignerAdapter<S, ssi_jwk::Algorithm, AnySignatureProtocol>>)
        //     ),*
        // }

        // impl<'a, S: 'a + MessageSigner<ssi_jwk::Algorithm, AnySignatureProtocol>> Future for Sign<'a, S> {
        //     type Output = Result<AnySignature, SignatureError>;

        //     fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        //         match self.project() {
        //             $(
        //                 $(#[cfg($($t)*)])?
        //                 SignProj::$name(s) => {
        //                     s.poll(cx).map_ok(Into::into)
        //                 }
        //             ),*
        //         }
        //     }
        // }

        impl SignatureAlgorithm<AnyMethod> for AnySignatureAlgorithm {
            type Options = AnySuiteOptions;

            type Signature = AnySignature;

            type Protocol = AnySignatureProtocol;

            type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

            // type Sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>> = FailibleFuture<Sign<'a, S>, SignatureError>;

            async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
                &self,
                options: <Self::Options as Referencable>::Reference<'_>,
                method: <AnyMethod as Referencable>::Reference<'_>,
                bytes: &[u8],
                signer: S
            ) -> Result<Self::Signature, SignatureError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(a) => {
                            eprintln!(concat!("cs algorithm is ", stringify!($name)));
                            match method.try_into() {
                                Ok(method) => {
                                    match options.try_into() {
                                        Ok(options) => {
                                            Ok(a.sign(
                                                options,
                                                method,
                                                bytes,
                                                SignerAdapter::new(signer)
                                            ).await?.into())
                                        }
                                        Err(e) => {
                                            Err(e.into())
                                        }
                                    }
                                }
                                Err(e) => {
                                    Err(e.into())
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
            type Transformed = Transformed;
            type Hashed = Hashed;

            type VerificationMethod = AnyMethod;

            type Signature = AnySignature;

            type SignatureProtocol = AnySignatureProtocol;

            type SignatureAlgorithm = AnySignatureAlgorithm;

            type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

            type Options = AnySuiteOptions;

            fn iri(&self) -> &iref::Iri {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_vc_data_integrity::suite::$name.iri()
                    ),*
                }
            }

            fn cryptographic_suite(&self) -> Option<&str> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_vc_data_integrity::suite::$name.cryptographic_suite()
                    ),*
                }
            }

            fn hash(&self, data: Transformed, proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>) -> Result<Self::Hashed, HashError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            ssi_vc_data_integrity::suite::$name.hash(
                                data.try_into()?,
                                proof_configuration
                                    .try_cast_verification_method()
                                    .map_err(|_| HashError::InvalidVerificationMethod)?
                            ).map(Into::into)
                        }
                    ),*
                }
            }

            fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => AnySignatureAlgorithm::$name(ssi_vc_data_integrity::suite::$name.setup_signature_algorithm())
                    ),*
                }
            }
        }
    };
}

#[derive(Debug, Clone)]
pub enum Hashed {
    Array32([u8; 32]),
    Array64([u8; 64]),
    Array66([u8; 66]),
    Vec(Vec<u8>),
    String(String),
}

impl AsRef<[u8]> for Hashed {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Array32(a) => a.as_ref(),
            Self::Array64(a) => a.as_ref(),
            Self::Array66(a) => a.as_ref(),
            Self::Vec(v) => v.as_ref(),
            Self::String(s) => s.as_bytes(),
        }
    }
}

impl From<[u8; 32]> for Hashed {
    fn from(value: [u8; 32]) -> Self {
        Self::Array32(value)
    }
}

impl From<[u8; 64]> for Hashed {
    fn from(value: [u8; 64]) -> Self {
        Self::Array64(value)
    }
}

impl From<[u8; 66]> for Hashed {
    fn from(value: [u8; 66]) -> Self {
        Self::Array66(value)
    }
}

impl From<Vec<u8>> for Hashed {
    fn from(value: Vec<u8>) -> Self {
        Self::Vec(value)
    }
}

impl From<String> for Hashed {
    fn from(value: String) -> Self {
        Self::String(value)
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

    #[cfg(feature = "w3c")]
    ethereum_eip712_signature_2021: EthereumEip712Signature2021,

    #[cfg(feature = "w3c")]
    ethereum_eip712_signature_2021_v0_1: EthereumEip712Signature2021v0_1,

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
    aleo_signature_2021: AleoSignature2021,

    /// Unspecified Tezos Ed25519 Blake2b, digest size 20, base 58 check encoded, Signature 2021.
    #[cfg(feature = "tezos")]
    ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021: Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos P256 Blake2b, digest size 20, base 58 check encoded, Signature 2021.
    #[cfg(feature = "tezos")]
    p256_blake2b_digest_size20_base58_check_encoded_signature_2021: P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos JCS Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_jcs_signature_2021: TezosJcsSignature2021,

    /// Unspecified Tezos Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_signature_2021: TezosSignature2021,

    #[cfg(feature = "eip712")]
    eip712_signature_2021: Eip712Signature2021,

    // #[cfg(feature = "ethereum")]
    ethereum_personal_signature_2021: EthereumPersonalSignature2021,

    ethereum_personal_signature_2021_v0_1: EthereumPersonalSignature2021v0_1
}

impl AnySuite {
    pub fn requires_eip721(&self) -> bool {
        if cfg!(feature = "w3c") {
            matches!(self, Self::EthereumEip712Signature2021)
        } else {
            false
        }
    }

    pub fn requires_eip721_v0_1(&self) -> bool {
        if cfg!(feature = "w3c") {
            matches!(self, Self::EthereumEip712Signature2021v0_1)
        } else {
            false
        }
    }

    pub fn requires_public_key_jwk(&self) -> bool {
        if cfg!(feature = "tezos") {
            matches!(
                self,
                Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    | Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    | Self::TezosSignature2021
            )
        } else {
            false
        }
    }

    pub fn requires_public_key_multibase(&self) -> bool {
        if cfg!(feature = "tezos") {
            matches!(self, Self::TezosJcsSignature2021)
        } else {
            false
        }
    }

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
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
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
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
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
                #[allow(unreachable_code)]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    #[cfg(feature = "tezos")]
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "dif")]
                    return Some(Self::EcdsaSecp256k1RecoverySignature2020);

                    return None;
                }
                #[cfg(feature = "secp256k1")]
                _ => Self::EcdsaSecp256k1Signature2019,

                #[allow(unreachable_patterns)]
                _ => return None,
            },
            Algorithm::ES256KR => {
                // #[allow(clippy::if_same_then_else)]
                #[cfg(feature = "eip712")]
                if use_eip712sig(jwk) {
                    return Some(Self::EthereumEip712Signature2021);
                }
                #[cfg(feature = "eip712")]
                if use_epsig(jwk) {
                    return Some(Self::EthereumPersonalSignature2021);
                }
                match verification_method {
                    #[cfg(feature = "eip712")]
                    Some(vm)
                        if (vm.id().starts_with("did:ethr:")
                            || vm.id().starts_with("did:pkh:eth:"))
                            && vm.id().ends_with("#Eip712Method2021") =>
                    {
                        Self::Eip712Signature2021
                    }
                    #[cfg(all(feature = "dif", feature = "secp256k1"))]
                    _ => Self::EcdsaSecp256k1RecoverySignature2020,

                    #[allow(unreachable_patterns)]
                    _ => return None,
                }
            }
            _ => return None,
        })
    }
}

#[cfg(feature = "eip712")]
fn use_eip712sig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signTypedData" key operation value to indicate using EthereumEip712Signature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signTypedData".to_string()) {
            return true;
        }
    }
    false
}

#[cfg(feature = "eip712")]
fn use_epsig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signPersonalMessage" key operation value to indicate using EthereumPersonalSignature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signPersonalMessage".to_string()) {
            return true;
        }
    }
    false
}

impl SigningMethod<JWK, ssi_jwk::Algorithm> for AnyMethod {
    fn sign_bytes_ref(
        this: AnyMethodRef,
        secret: &JWK,
        algorithm: ssi_jwk::Algorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match this {
            AnyMethodRef::RsaVerificationKey2018(_) => todo!(),
            AnyMethodRef::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::Ed25519VerificationKey2020(_) => todo!(),
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                match algorithm {
                    ssi_jwk::Algorithm::ES256K => {
                        m.sign_bytes(
                            secret,
                            ssi_verification_methods::ecdsa_secp_256k1_verification_key_2019::DigestFunction::Sha256,
                            bytes
                        )
                    }
                    _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                        algorithm.to_string(),
                    )),
                }
            },
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => match algorithm {
                ssi_jwk::Algorithm::ES256KR => {
                    m.sign_bytes(secret, ssi_jwk::algorithm::ES256KR, bytes)
                }
                ssi_jwk::Algorithm::ESKeccakKR => {
                    m.sign_bytes(secret, ssi_jwk::algorithm::ESKeccakKR, bytes)
                }
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            AnyMethodRef::EcdsaSecp256r1VerificationKey2019(m) => {
                match algorithm {
                    ssi_jwk::Algorithm::ES256 => {
                        m.sign_bytes(secret, bytes)
                    }
                    _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                        algorithm.to_string(),
                    ))
                }
            },
            AnyMethodRef::JsonWebKey2020(_) => todo!(),
            AnyMethodRef::Multikey(_) => todo!(),
            AnyMethodRef::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::TezosMethod2021(m) => m.sign_bytes(secret, algorithm.try_into()?, bytes),
            AnyMethodRef::AleoMethod2021(_) => todo!(),
            AnyMethodRef::BlockchainVerificationMethod2021(_) => todo!(),
            AnyMethodRef::Eip712Method2021(m) => {
                SigningMethod::sign_bytes(m, secret, algorithm.try_into()?, bytes)
            },
            AnyMethodRef::SolanaMethod2021(_) => todo!(),
        }
    }
}
