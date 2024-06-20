macro_rules! crypto_suites {
    {
        $(
            $(#[doc = $doc:literal])*
            $(#[cfg($($t:tt)*)])?
            $field_name:ident: $name:ident
        ),*
    } => {
        /// Built-in Data Integrity cryptographic suites.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum AnySuite {
            $(
                $(#[doc = $doc])*
                $(#[cfg($($t)*)])?
                $name,
            )*

            /// Unknown cryptographic suite.
            ///
            /// This variant exists to ensure that it will always be possible
            /// to parse a verifiable credential or presentation secured with
            /// `AnySuite`, even if the suite is not supported by this
            /// library.
            Unknown(UnknownSuite)
        }

        impl ssi_data_integrity_core::CryptographicSuite for AnySuite {
			type Configuration = AnyConfigurationAlgorithm;

            type PreparedClaims = AnyPreparedClaims;

            type VerificationMethod = AnySuiteVerificationMethod;

            type Signature = AnySignature;

            type ProofOptions = AnyProofOptions;

            fn type_(&self) -> ssi_data_integrity_core::TypeRef {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => ssi_data_integrity_suites::$name.type_(),
                    )*
                    Self::Unknown(suite) => suite.type_.as_ref()
                }
            }
        }

        #[allow(unused)]
        trait Project<S: ssi_data_integrity_core::CryptographicSuite>: ssi_data_integrity_core::CryptographicSuite {
            fn project_input_options(
                options: ssi_data_integrity_core::suite::InputOptions<Self>
            ) -> Result<ssi_data_integrity_core::suite::InputOptions<S>, ssi_data_integrity_core::suite::ConfigurationError>;

            fn project_prepared_claims(
                prepared_claims: &Self::PreparedClaims
            ) -> &S::PreparedClaims;

            fn project_proof_configuration(
                proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<Self>
            ) -> ssi_data_integrity_core::ProofConfigurationRef<S>;

            fn project_proof(
                proof: ssi_data_integrity_core::ProofRef<Self>
            ) -> ssi_data_integrity_core::ProofRef<S>;
        }

        $(
            $(#[cfg($($t)*)])?
            #[allow(unused_variables)]
            impl Project<ssi_data_integrity_suites::$name> for AnySuite {
                fn project_input_options(
                    options: ssi_data_integrity_core::ProofOptions<ssi_verification_methods::AnyMethod, crate::AnyInputSuiteOptions>
                ) -> Result<ssi_data_integrity_core::ProofOptions<ssi_data_integrity_core::suite::InputVerificationMethod<ssi_data_integrity_suites::$name>, ssi_data_integrity_core::suite::InputSuiteOptions<ssi_data_integrity_suites::$name>>, ssi_data_integrity_core::suite::ConfigurationError> {
                    options.try_map::<_, _, ssi_data_integrity_core::suite::ConfigurationError>(
                        |method| method.try_into().map_err(ssi_data_integrity_core::suite::ConfigurationError::other),
                        |options| options.try_into().map_err(Into::into)
                    )
                }

                fn project_prepared_claims(
                    prepared_claims: &Self::PreparedClaims
                ) -> &<ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::PreparedClaims {
                    match prepared_claims {
                        AnyPreparedClaims::$name(c) => c,
                        _ => panic!("malformed `AnySuite` instance")
                    }
                }

                fn project_proof_configuration(
                    proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<Self>
                ) -> ssi_data_integrity_core::ProofConfigurationRef<ssi_data_integrity_suites::$name> {
                    proof_configuration.map(
                        |_| &ssi_data_integrity_suites::$name,
                        |method| match method {
                            AnySuiteVerificationMethod::$name(m) => m,
                            _ => panic!("malformed `AnySuite` instance")
                        },
                        |options| match options {
                            AnyProofOptions::$name(m) => m,
                            _ => panic!("malformed `AnySuite` instance")
                        }
                    )
                }

                fn project_proof(
                    proof: ssi_data_integrity_core::ProofRef<Self>
                ) -> ssi_data_integrity_core::ProofRef<ssi_data_integrity_suites::$name> {
                    proof.map(
                        |_| &ssi_data_integrity_suites::$name,
                        |method| match method {
                            AnySuiteVerificationMethod::$name(m) => m,
                            _ => panic!("malformed `AnySuite` instance")
                        },
                        |options| match options {
                            AnyProofOptions::$name(m) => m,
                            _ => panic!("malformed `AnySuite` instance")
                        },
                        |signature| match signature {
                            AnySignature::$name(s) => s,
                            _ => panic!("malformed `AnySuite` instance")
                        }
                    )
                }
            }
        )*

        #[allow(unused_variables)]
        impl<T, C, V, I, L> ssi_data_integrity_core::suite::CryptographicSuiteInstance<T, C> for AnySuite
        where
            C: ssi_json_ld::AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>
                + ssi_data_integrity_suites::eip712::TypesProvider,
            V: rdf_types::VocabularyMut,
            V::Iri: Clone + Eq + std::hash::Hash + linked_data::LinkedDataSubject<I, V> + linked_data::LinkedDataResource<I, V>,
            V::BlankId: Clone + Eq + std::hash::Hash + linked_data::LinkedDataSubject<I, V> + linked_data::LinkedDataResource<I, V>,
            I: rdf_types::InterpretationMut<V>
                + rdf_types::interpretation::ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
            I::Resource: Clone,
            L: json_ld::Loader<V::Iri>,
            L::Error: std::fmt::Display,
            T: serde::Serialize + ssi_rdf::Expandable<C> + ssi_json_ld::JsonLdNodeObject,
            T::Expanded: linked_data::LinkedData<I, V>
        {
            async fn prepare_claims(
                &self,
                context: &mut C,
                unsecured_document: &T,
                proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<'_, Self>,
            ) -> Result<Self::PreparedClaims, ssi_data_integrity_core::suite::ClaimsPreparationError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuiteInstance<T, C>>::prepare_claims(
                                &ssi_data_integrity_suites::$name,
                                context,
                                unsecured_document,
                                Self::project_proof_configuration(proof_configuration)
                            ).await.map(AnyPreparedClaims::$name)
                        },
                    )*
                    Self::Unknown(_) => {
                        Ok(AnyPreparedClaims::Unknown)
                    }
                }
            }
        }

        #[allow(unused_variables)]
        impl<R, S> ssi_data_integrity_core::suite::CryptographicSuiteSigning<R, S> for AnySuite
        where
            R: ssi_verification_methods::VerificationMethodResolver<Method = ssi_verification_methods::AnyMethod>,
            S: ssi_verification_methods::Signer<ssi_verification_methods::AnyMethod>,
            S::MessageSigner: ssi_verification_methods::MessageSigner<crate::AnySignatureAlgorithm>
        {
            async fn sign_prepared_claims(
                &self,
                resolver: R,
                signer: S,
                prepared_claims: &AnyPreparedClaims,
                proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<'_, Self>,
            ) -> Result<Self::Signature, ssi_claims_core::SignatureError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            let signer = crate::AnySigner(signer);
                            let resolver = crate::AnyResolver::<_, <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuite>::VerificationMethod>::new(resolver);

                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuiteSigning<_, _>>::sign_prepared_claims(
                                &ssi_data_integrity_suites::$name,
                                resolver,
                                signer,
                                <Self as Project<ssi_data_integrity_suites::$name>>::project_prepared_claims(prepared_claims),
                                Self::project_proof_configuration(proof_configuration)
                            ).await.map(AnySignature::$name)
                        },
                    )*
                    Self::Unknown(suite) => {
                        Err(ssi_claims_core::SignatureError::other(format!("unsupported cryptographic suite {}", suite.type_)))
                    }
                }
            }
        }

        #[allow(unused_variables)]
        impl<V> ssi_data_integrity_core::suite::CryptographicSuiteVerification<V> for AnySuite
        where
            V: ssi_verification_methods::VerificationMethodResolver<Method = ssi_verification_methods::AnyMethod>,
        {
            async fn verify_prepared_claims(
                &self,
                verifier: &V,
                prepared_claims: &AnyPreparedClaims,
                proof: ssi_data_integrity_core::ProofRef<'_, Self>,
            ) -> Result<ssi_claims_core::ProofValidity, ssi_claims_core::ProofValidationError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            let verifier = crate::AnyResolver::<_, <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuite>::VerificationMethod>::new(verifier);

                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuiteVerification<_>>::verify_prepared_claims(
                                &ssi_data_integrity_suites::$name,
                                &verifier,
                                <Self as Project<ssi_data_integrity_suites::$name>>::project_prepared_claims(prepared_claims),
                                Self::project_proof(proof)
                            ).await
                        },
                    )*
                    Self::Unknown(suite) => {
                        Err(ssi_claims_core::ProofValidationError::other(format!("unsupported cryptographic suite {}", suite.type_)))
                    }
                }
            }
        }

        impl From<ssi_data_integrity_core::Type> for AnySuite {
            fn from(
                ty: ssi_data_integrity_core::Type
            ) -> Self {
                $(
                    $(#[cfg($($t)*)])?
                    {
                        let suite = ssi_data_integrity_suites::$name;
                        if ty == <ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::type_(&suite) {
                            return Self::$name
                        }
                    }
                )*

                Self::Unknown(UnknownSuite::new(ty))
            }
        }

        /// Any verification method.
        #[derive(Debug, Clone, serde::Serialize)]
        #[serde(untagged)]
        pub enum AnySuiteVerificationMethod {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::VerificationMethod),
            )*
            Unknown(ssi_verification_methods::GenericVerificationMethod)
        }

        impl ssi_verification_methods::VerificationMethod for AnySuiteVerificationMethod {
            fn id(&self) -> &iref::Iri {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(m) => m.id(),
                    )*
                    Self::Unknown(m) => &m.id
                }
            }

            fn controller(&self) -> Option<&iref::Iri> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(m) => m.controller(),
                    )*
                    Self::Unknown(m) => Some(m.controller.as_iri())
                }
            }
        }

        impl From<AnySuiteVerificationMethod> for ssi_verification_methods::AnyMethod {
            fn from(value: AnySuiteVerificationMethod) -> Self {
                match value {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuiteVerificationMethod::$name(m) => m.into(),
                    )*
                    AnySuiteVerificationMethod::Unknown(m) => ssi_verification_methods::AnyMethod::Unknown(m)
                }
            }
        }

        impl<'de> ssi_core::de::DeserializeTyped<'de, AnySuite> for AnySuiteVerificationMethod {
            fn deserialize_typed<D>(
                suite: &AnySuite,
                deserializer: D
            ) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>
            {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            serde::Deserialize::deserialize(deserializer).map(Self::$name)
                        },
                    )*
                    _ => serde::Deserialize::deserialize(deserializer).map(Self::Unknown)
                }
            }
        }

        /// Any hashed document.
        #[derive(Debug, Clone, serde::Serialize)]
        #[serde(untagged)]
        pub enum AnySignature {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::Signature),
            )*
            Unknown
        }

        impl AsRef<str> for AnySignature {
            fn as_ref(&self) -> &str {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(s) => s.as_ref(),
                    )*
                    Self::Unknown => ""
                }
            }
        }

        impl ssi_data_integrity_core::signing::AlterSignature for AnySignature {
            fn alter(&mut self) {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name(s) => {
                            ssi_data_integrity_core::signing::AlterSignature::alter(s)
                        }
                    )*
                    Self::Unknown => ()
                }
            }
        }

        #[allow(unused_variables)]
        impl<'de> ssi_core::de::DeserializeTyped<'de, AnySuite> for AnySignature {
            fn deserialize_typed<D>(
                suite: &AnySuite,
                deserializer: D
            ) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>
            {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            serde::Deserialize::deserialize(deserializer).map(AnySignature::$name)
                        },
                    )*
                    _ => Ok(AnySignature::Unknown)
                }
            }
        }

        /// Any signature protocol.
        #[derive(Debug, Clone, serde::Serialize)]
        #[serde(untagged)]
        pub enum AnyProofOptions {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::ProofOptions),
            )*
            Unknown
        }

        #[allow(unused_variables)]
        impl<'de> ssi_core::de::DeserializeTyped<'de, AnySuite> for AnyProofOptions {
            fn deserialize_typed<D>(
                suite: &AnySuite,
                deserializer: D
            ) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>
            {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            serde::Deserialize::deserialize(deserializer).map(AnyProofOptions::$name)
                        },
                    )*
                    _ => Ok(AnyProofOptions::Unknown)
                }
            }
        }

        impl From<AnyProofOptions> for crate::AnyInputSuiteOptions {
            fn from(value: AnyProofOptions) -> Self {
                match value {
                    $(
                        $(#[cfg($($t)*)])?
                        AnyProofOptions::$name(o) => o.into(),
                    )*
                    AnyProofOptions::Unknown => Self::default()
                }
            }
        }

        pub struct AnyConfigurationAlgorithm;

        #[allow(unused_variables)]
        impl ssi_data_integrity_core::suite::ConfigurationAlgorithm<AnySuite> for AnyConfigurationAlgorithm {
            type InputVerificationMethod = ssi_verification_methods::AnyMethod;
            type InputSuiteOptions = crate::AnyInputSuiteOptions;

            fn configure(suite: &AnySuite, options: ssi_data_integrity_core::suite::InputOptions<AnySuite>) -> Result<ssi_data_integrity_core::ProofConfiguration<AnySuite>, ssi_data_integrity_core::suite::ConfigurationError> {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            let options = <AnySuite as Project<ssi_data_integrity_suites::$name>>::project_input_options(
                                options
                            )?;

                            let proof_configuration = <ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::configure(
                                &ssi_data_integrity_suites::$name,
                                options
                            )?;

                            Ok(proof_configuration.map(
                                |_| AnySuite::$name,
                                |m| AnySuiteVerificationMethod::$name(m),
                                |o| AnyProofOptions::$name(o)
                            ))
                        },
                    )*
                    AnySuite::Unknown(_) => options.map(
                        |m| AnySuiteVerificationMethod::Unknown(m.into()),
                        |_| AnyProofOptions::Unknown
                    ).into_configuration(suite.clone())
                }
            }
        }

        #[derive(Debug, Clone)]
        pub enum AnyPreparedClaims {
            $(
                $(#[cfg($($t)*)])?
                $name(<ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::PreparedClaims),
            )*
            Unknown
        }
    };
}

pub(crate) use crypto_suites;
