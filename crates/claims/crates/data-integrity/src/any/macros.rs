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
        pub(crate) trait Project<S: ssi_data_integrity_core::CryptographicSuite>: ssi_data_integrity_core::CryptographicSuite {
            fn project_input_options(
                options: ssi_data_integrity_core::suite::InputProofOptions<Self>
            ) -> Result<ssi_data_integrity_core::suite::InputProofOptions<S>, ssi_data_integrity_core::suite::ConfigurationError>;

            fn project_prepared_claims(
                prepared_claims: &Self::PreparedClaims
            ) -> &S::PreparedClaims;

            fn project_proof_configuration(
                proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<Self>
            ) -> ssi_data_integrity_core::ProofConfigurationRef<S>;

            fn project_proof(
                proof: ssi_data_integrity_core::ProofRef<Self>
            ) -> ssi_data_integrity_core::ProofRef<S>;

            fn project_transformation_options(
                options: AnyTransformationOptions
            ) -> ssi_data_integrity_core::suite::TransformationOptions<S>;
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

                fn project_transformation_options(
                    options: AnyTransformationOptions
                ) -> ssi_data_integrity_core::suite::TransformationOptions<ssi_data_integrity_suites::$name> {
                    match options {
                        AnyTransformationOptions::$name(o) => o,
                        _ => panic!("malformed `AnySuite` instance")
                    }
                }
            }
        )*

        #[allow(unused_variables)]
        impl<T, C, R, S> ssi_data_integrity_core::suite::CryptographicSuiteSigning<T, C, R, S> for AnySuite
        where
            C: ssi_json_ld::JsonLdLoaderProvider
                + ssi_eip712::Eip712TypesLoaderProvider,
            T: serde::Serialize + ssi_json_ld::Expandable + ssi_json_ld::JsonLdNodeObject,
            T::Expanded<ssi_rdf::LexicalInterpretation, ()>: Into<ssi_json_ld::ExpandedDocument>,
            //
            R: ssi_verification_methods::VerificationMethodResolver<Method = ssi_verification_methods::AnyMethod>,
            S: ssi_verification_methods::Signer<ssi_verification_methods::AnyMethod>,
            S::MessageSigner: ssi_verification_methods::MessageSigner<crate::AnySignatureAlgorithm>
        {
            async fn generate_signature(
                &self,
                context: &C,
                resolver: R,
                signer: S,
                claims: &T,
                proof_configuration: ssi_data_integrity_core::ProofConfigurationRef<'_, Self>,
                transformation_options: AnyTransformationOptions
            ) -> Result<Self::Signature, ssi_claims_core::SignatureError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            let signer = crate::AnySigner(signer);
                            let resolver = crate::AnyResolver::<_, <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuite>::VerificationMethod>::new(resolver);

                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuiteSigning<_, _, _, _>>::generate_signature(
                                &ssi_data_integrity_suites::$name,
                                context,
                                resolver,
                                signer,
                                claims,
                                Self::project_proof_configuration(proof_configuration),
                                <Self as Project<ssi_data_integrity_suites::$name>>::project_transformation_options(transformation_options)
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
        impl<T, V> ssi_data_integrity_core::suite::CryptographicSuiteVerification<T, V> for AnySuite
        where
            T: serde::Serialize + ssi_json_ld::Expandable + ssi_json_ld::JsonLdNodeObject,
            T::Expanded<ssi_rdf::LexicalInterpretation, ()>: Into<ssi_json_ld::ExpandedDocument>,
            V: ssi_claims_core::ResolverProvider + ssi_json_ld::JsonLdLoaderProvider + ssi_eip712::Eip712TypesLoaderProvider,
            V::Resolver: ssi_verification_methods::VerificationMethodResolver<Method = ssi_verification_methods::AnyMethod>,
        {
            async fn verify_proof(
                &self,
                verifier: &V,
                claims: &T,
                proof: ssi_data_integrity_core::ProofRef<'_, Self>,
                transformation_options: AnyTransformationOptions
            ) -> Result<ssi_claims_core::ProofValidity, ssi_claims_core::ProofValidationError> {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
                            let verifier = AnyVerifier {
                                resolver: crate::AnyResolver::<_, <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuite>::VerificationMethod>::new(verifier.resolver()),
                                json_ld_loader: verifier.loader(),
                                eip712_loader: verifier.eip712_types()
                            };

                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::suite::CryptographicSuiteVerification<_, _>>::verify_proof(
                                &ssi_data_integrity_suites::$name,
                                &verifier,
                                claims,
                                Self::project_proof(proof),
                                <Self as Project<ssi_data_integrity_suites::$name>>::project_transformation_options(transformation_options)
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

        /// Any signature.
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

        /// Any transformation options.
        pub enum AnyTransformationOptions {
            $(
                $(#[cfg($($t)*)])?
                $name(ssi_data_integrity_core::suite::TransformationOptions<ssi_data_integrity_suites::$name>),
            )*
            Unknown
        }

        pub struct AnyConfigurationAlgorithm;

        #[allow(unused_variables)]
        impl ssi_data_integrity_core::suite::ConfigurationAlgorithm<AnySuite> for AnyConfigurationAlgorithm {
            type InputVerificationMethod = ssi_verification_methods::AnyMethod;
            type InputSuiteOptions = crate::AnyInputSuiteOptions;
            type InputSignatureOptions = AnySignatureOptions;
            type InputVerificationOptions = ();
            type TransformationOptions = AnyTransformationOptions;

            fn configure_signature(
                suite: &AnySuite,
                options: ssi_data_integrity_core::suite::InputProofOptions<AnySuite>,
                signature_options: AnySignatureOptions
            ) -> Result<(ssi_data_integrity_core::ProofConfiguration<AnySuite>, AnyTransformationOptions), ssi_data_integrity_core::suite::ConfigurationError> {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            let options = <AnySuite as Project<ssi_data_integrity_suites::$name>>::project_input_options(
                                options
                            )?;

                            let (proof_configuration, transformation_options) = <ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::configure_signature(
                                &ssi_data_integrity_suites::$name,
                                options,
                                signature_options.try_into()?
                            )?;

                            Ok((proof_configuration.map(
                                |_| AnySuite::$name,
                                |m| AnySuiteVerificationMethod::$name(m),
                                |o| AnyProofOptions::$name(o)
                            ), AnyTransformationOptions::$name(transformation_options)))
                        },
                    )*
                    AnySuite::Unknown(_) => Ok((
                        options.map(
                            |m| AnySuiteVerificationMethod::Unknown(m.into()),
                            |_| AnyProofOptions::Unknown
                        ).into_configuration(suite.clone())?,
                        AnyTransformationOptions::Unknown
                    ))
                }
            }

            fn configure_verification(
                suite: &AnySuite,
                verification_options: &()
            ) -> Result<AnyTransformationOptions, ssi_data_integrity_core::suite::ConfigurationError> {
                match suite {
                    $(
                        $(#[cfg($($t)*)])?
                        AnySuite::$name => {
                            <ssi_data_integrity_suites::$name as ssi_data_integrity_core::CryptographicSuite>::configure_verification(
                                &ssi_data_integrity_suites::$name,
                                verification_options
                            ).map(AnyTransformationOptions::$name)
                        },
                    )*
                    AnySuite::Unknown(_) => Ok(AnyTransformationOptions::Unknown)
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
