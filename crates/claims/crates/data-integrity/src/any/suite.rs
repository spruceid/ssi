use iref::Iri;
use linked_data::{LinkedDataDeserializePredicateObjects, LinkedDataDeserializeSubject};
use rdf_types::{
    dataset::PatternMatchingDataset, interpretation::ReverseIriInterpretation, Interpretation,
    Vocabulary,
};
use ssi_claims_core::ProofValidity;
use ssi_core::Referencable;
use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{
    suite::HashError, CryptographicSuite, ExpandedConfiguration, UnsupportedProofSuite,
};
use ssi_jwk::JWK;
use ssi_verification_methods::{
    AnyMethod, AnyMethodRef, ReferenceOrOwned, SignatureError, VerificationError,
};

use super::{
    AnyHash, AnySignature, AnySignatureRef, AnySuiteOptions, AnySuiteOptionsRef, Transformed,
};
use crate::AnySignatureProtocol;

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializePredicateObjects<I, V> for AnySuite
where
    I: ReverseIriInterpretation<Iri = V::Iri>,
{
    fn deserialize_objects_in<'a, D>(
        vocabulary: &V,
        interpretation: &I,
        dataset: &D,
        graph: Option<&I::Resource>,
        objects: impl IntoIterator<Item = &'a I::Resource>,
        context: linked_data::Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        I::Resource: 'a,
        D: PatternMatchingDataset<Resource = I::Resource>,
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

        impl TryFrom<ssi_data_integrity_core::Type> for AnySuite {
            type Error = UnsupportedProofSuite;

            fn try_from(
                ty: ssi_data_integrity_core::Type
            ) -> Result<Self, Self::Error> {
                $(
                    $(#[cfg($($t)*)])?
                    {
                        let suite = ssi_data_integrity_suites::$name;
                        if suite.name() == ty.name && suite.cryptographic_suite() == ty.cryptosuite.as_deref() {
                            return Ok(Self::$name)
                        }
                    }
                )*

                Err(UnsupportedProofSuite::Compact(ty))
            }
        }

        impl TryFrom<ssi_data_integrity_core::ExpandedType> for AnySuite {
            type Error = UnsupportedProofSuite;

            fn try_from(
                ty: ssi_data_integrity_core::ExpandedType
            ) -> Result<Self, Self::Error> {
                $(
                    $(#[cfg($($t)*)])?
                    {
                        let suite = ssi_data_integrity_suites::$name;
                        if *suite.iri() == ty.iri && suite.cryptographic_suite() == ty.cryptosuite.as_deref() {
                            return Ok(Self::$name)
                        }
                    }
                )*

                Err(UnsupportedProofSuite::Expanded(ty))
            }
        }

        impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializeSubject<I, V> for AnySuite
        where
            I: ReverseIriInterpretation<Iri = V::Iri>
        {
            fn deserialize_subject_in<D>(
                vocabulary: &V,
                interpretation: &I,
                _dataset: &D,
                _graph: Option<&I::Resource>,
                resource: &I::Resource,
                context: linked_data::Context<I>
            ) -> Result<Self, linked_data::FromLinkedDataError>
            where
                D: PatternMatchingDataset<Resource = I::Resource>
            {
                let mut known_iri = None;

                for i in interpretation.iris_of(resource) {
                    let iri = vocabulary.iri(i).unwrap();
                    known_iri = Some(iri);
                    $(
                        $(#[cfg($($t)*)])?
                        if iri == ssi_data_integrity_suites::$name::IRI {
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
                                    ssi_data_integrity_suites::$name::IRI.to_owned(),
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

        // #[async_trait::async_trait]
        impl CryptographicSuite for AnySuite {
            type Transformed = Transformed;
            type Hashed = AnyHash;

            type VerificationMethod = AnyMethod;

            type Signature = AnySignature;

            type SignatureProtocol = AnySignatureProtocol;

            type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

            type Options = AnySuiteOptions;

            fn name(&self) -> &str {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_data_integrity_suites::$name.name(),
                    )*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            fn iri(&self) -> &iref::Iri {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_data_integrity_suites::$name.iri(),
                    )*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            fn cryptographic_suite(&self) -> Option<&str> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_data_integrity_suites::$name.cryptographic_suite(),
                    )*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            #[allow(unused)]
            fn refine_type(&mut self, type_: &Iri) -> Result<(), UnsupportedProofSuite> {
                let current_cryptosuite = self.cryptographic_suite();

                $(
                    $(#[cfg($($t)*)])?
                    {
                        let suite = ssi_data_integrity_suites::$name;
                        if suite.iri() == type_ && suite.cryptographic_suite() == current_cryptosuite {
                            *self = Self::$name;
                            return Ok(())
                        }
                    }
                )*

                Err(UnsupportedProofSuite::Expanded(ssi_data_integrity_core::ExpandedType { iri: type_.to_owned(), cryptosuite: self.cryptographic_suite().map(ToOwned::to_owned) }))
            }

            #[allow(unused)]
            fn hash(&self, data: Transformed, proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>) -> Result<Self::Hashed, HashError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            ssi_data_integrity_suites::$name.hash(
                                data.try_into()?,
                                proof_configuration
                                    .try_cast_verification_method()
                                    .map_err(|_| HashError::InvalidVerificationMethod)?
                            ).map(Into::into)
                        }
                    ),*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_data_integrity_suites::$name.required_proof_context(),
                    )*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            #[allow(unused)]
            async fn sign_hash(
                &self,
                options: <Self::Options as Referencable>::Reference<'_>,
                method: <AnyMethod as Referencable>::Reference<'_>,
                bytes: &Self::Hashed,
                signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>
            ) -> Result<Self::Signature, SignatureError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            match method.try_into() {
                                Ok(method) => {
                                    match options.try_into() {
                                        Ok(options) => {
                                            Ok(ssi_data_integrity_suites::$name.sign_hash(
                                                options,
                                                method,
                                                bytes.try_into()?,
                                                ssi_crypto::SignerAdapter::new(signer)
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
                    )*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }

            #[allow(unused)]
            fn verify_hash(
                &self,
                options: AnySuiteOptionsRef,
                method: AnyMethodRef,
                bytes: &Self::Hashed,
                signature: AnySignatureRef
            ) -> Result<ProofValidity, VerificationError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            ssi_data_integrity_suites::$name.verify_hash(
                                options.try_into()?,
                                method.try_into()?,
                                bytes.try_into()?,
                                signature.try_into()?
                            )
                        }
                    ),*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
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
    json_web_signature_2020: JsonWebSignature2020,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    ethereum_eip712_signature_2021: EthereumEip712Signature2021,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
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
    #[cfg(all(feature = "tezos", feature = "ed25519"))]
    ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021: Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos P256 Blake2b, digest size 20, base 58 check encoded, Signature 2021.
    #[cfg(all(feature = "tezos", feature = "secp256r1"))]
    p256_blake2b_digest_size20_base58_check_encoded_signature_2021: P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos JCS Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_jcs_signature_2021: TezosJcsSignature2021,

    /// Unspecified Tezos Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_signature_2021: TezosSignature2021,

    #[cfg(all(feature = "ethereum", feature = "eip712"))]
    eip712_signature_2021: Eip712Signature2021,

    #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
    ethereum_personal_signature_2021: EthereumPersonalSignature2021,

    #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
    ethereum_personal_signature_2021_v0_1: EthereumPersonalSignature2021v0_1
}

impl AnySuite {
    #[cfg(feature = "eip712")]
    pub fn requires_eip721(&self) -> bool {
        #[cfg(feature = "w3c")]
        if matches!(self, Self::EthereumEip712Signature2021) {
            return true;
        }

        false
    }

    #[cfg(feature = "eip712")]
    pub fn requires_eip721_v0_1(&self) -> bool {
        #[cfg(feature = "w3c")]
        if matches!(self, Self::EthereumEip712Signature2021v0_1) {
            return true;
        }

        false
    }

    pub fn requires_public_key_jwk(&self) -> bool {
        #[cfg(all(feature = "tezos", feature = "ed25519"))]
        if matches!(
            self,
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        ) {
            return true;
        }

        #[cfg(all(feature = "tezos", feature = "secp256r1"))]
        if matches!(
            self,
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        ) {
            return true;
        }

        #[cfg(feature = "tezos")]
        if matches!(self, Self::TezosSignature2021) {
            return true;
        }

        false
    }

    pub fn requires_public_key_multibase(&self) -> bool {
        #[cfg(feature = "tezos")]
        if matches!(self, Self::TezosJcsSignature2021) {
            return true;
        }

        false
    }

    #[allow(unused)]
    pub fn pick(
        jwk: &JWK,
        verification_method: Option<&ReferenceOrOwned<AnyMethod>>,
    ) -> Option<Self> {
        if let Some(vm) = verification_method {
            #[cfg(feature = "w3c")]
            if vm.id().starts_with("did:jwk:") {
                return Some(Self::JsonWebSignature2020);
            }
        }

        use ssi_jwk::Algorithm;
        let algorithm = jwk.get_algorithm()?;
        match algorithm {
            #[cfg(all(feature = "w3c", feature = "rsa"))]
            Algorithm::RS256 => Some(Self::RsaSignature2018),
            #[cfg(feature = "w3c")]
            Algorithm::PS256 => Some(Self::JsonWebSignature2020),
            #[cfg(feature = "w3c")]
            Algorithm::ES384 => Some(Self::JsonWebSignature2020),
            #[cfg(feature = "aleo")]
            Algorithm::AleoTestnet1Signature => Some(Self::AleoSignature2021),
            Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
                #[cfg(feature = "solana")]
                Some(vm)
                    if (vm.id().starts_with("did:sol:") || vm.id().starts_with("did:pkh:sol:"))
                        && vm.id().ends_with("#SolanaMethod2021") =>
                {
                    Some(Self::SolanaSignature2021)
                }
                #[cfg(feature = "tezos")]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "ed25519")]
                    return Some(Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "ed25519"))]
                _ => Some(Self::Ed25519Signature2018),
                #[cfg(not(all(feature = "w3c", feature = "ed25519")))]
                _ => {
                    // missing `ed25519` or `tezos` or `solana`.
                    None
                }
            },
            Algorithm::ES256 | Algorithm::ESBlake2b => match verification_method {
                #[cfg(feature = "tezos")]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "secp256r1")]
                    return Some(Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "secp256r1"))]
                _ => Some(Self::EcdsaSecp256r1Signature2019),
                #[allow(unreachable_patterns)]
                _ => {
                    // missing `secp256r1` or `tezos` features.
                    None
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

                    #[cfg(all(feature = "dif", feature = "secp256k1"))]
                    return Some(Self::EcdsaSecp256k1RecoverySignature2020);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "secp256k1"))]
                _ => Some(Self::EcdsaSecp256k1Signature2019),
                #[allow(unreachable_patterns)]
                _ => None,
            },
            Algorithm::ES256KR => {
                // #[allow(clippy::if_same_then_else)]
                #[cfg(all(feature = "w3c", feature = "eip712"))]
                if use_eip712sig(jwk) {
                    return Some(Self::EthereumEip712Signature2021);
                }
                #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
                if use_epsig(jwk) {
                    return Some(Self::EthereumPersonalSignature2021);
                }

                match verification_method {
                    #[cfg(all(feature = "ethereum", feature = "eip712"))]
                    Some(vm)
                        if (vm.id().starts_with("did:ethr:")
                            || vm.id().starts_with("did:pkh:eth:"))
                            && vm.id().ends_with("#Eip712Method2021") =>
                    {
                        Some(Self::Eip712Signature2021)
                    }

                    #[cfg(all(feature = "dif", feature = "secp256k1"))]
                    _ => Some(Self::EcdsaSecp256k1RecoverySignature2020),
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
fn use_eip712sig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signTypedData" key operation value to indicate using EthereumEip712Signature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signTypedData".to_string()) {
            return true;
        }
    }
    false
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
fn use_epsig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signPersonalMessage" key operation value to indicate using EthereumPersonalSignature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signPersonalMessage".to_string()) {
            return true;
        }
    }
    false
}
