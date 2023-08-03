use crate::{suite::HashError, verification, CryptographicSuite, ProofConfiguration, ProofConfigurationRef};
use std::future::Future;
use std::pin::Pin;

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

        // #[async_trait::async_trait]
        impl CryptographicSuite for Suite {
            type Transformed = String;
            type Hashed = [u8; 64];

            type VerificationMethod = verification::MethodReferenceOrOwned<verification::method::Any>;

            type Signature = ssi_verification_methods::signature::Any;

            type Options = Options;

            fn iri(&self) -> iref::Iri {
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
                        Self::$name => super::$name.hash(
                            data,
                            proof_configuration
                                .try_cast_verification_method()
                                .map_err(|_| HashError::InvalidVerificationMethod)?
                        )
                    ),*
                }
            }

            fn generate_proof(
                &self,
                data: &Self::Hashed,
                signer: &impl ssi_crypto::Signer<Self::VerificationMethod, Self::Signature>,
                proof_configuration: ProofConfiguration<Self::VerificationMethod>,
                options: Options
            ) -> Result<crate::UntypedProof<Self::VerificationMethod, Self::Signature>, ssi_crypto::SignatureError> {
                use ssi_verification_methods::IntoAnyVerificationMethod;
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            let signer = ssi_verification_methods::AnySigner(signer);
                            super::$name.generate_proof(
                                data,
                                &signer,
                                proof_configuration
                                    .try_cast_verification_method()
                                    .map_err(|_| ssi_crypto::SignatureError::InvalidVerificationMethod)?,
                                options.$field_name
                            ).map(crate::UntypedProof::into_any_verification_method)
                        }
                    ),*
                }
            }

            fn verify_proof<'async_trait, 'd: 'async_trait, 'v: 'async_trait, 'p: 'async_trait>(
                &self,
                data: &'d Self::Hashed,
                verifier: &'v impl ssi_crypto::Verifier<Self::VerificationMethod, Self::Signature>,
                proof: crate::UntypedProofRef<'p, Self::VerificationMethod, Self::Signature>,
            ) -> Pin<Box<dyn 'async_trait + Send + Future<Output = Result<ssi_vc::ProofValidity, ssi_crypto::VerificationError>>>>
            where
                Self::VerificationMethod: 'async_trait,
                Self::Signature: 'async_trait
            {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => Box::pin(async move {
                            let verifier = ssi_verification_methods::AnyVerifier(verifier);
                            let proof = proof.try_cast_verification_method()?;
                            super::$name.verify_proof(
                                data,
                                &verifier,
                                proof
                            ).await
                        })
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
