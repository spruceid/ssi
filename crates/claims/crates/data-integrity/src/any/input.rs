use super::AnySuiteOptions;
use rdf_types::{
    generator,
    interpretation::{self, WithGenerator},
    IriVocabulary,
};
use ssi_data_integrity_core::{
    suite::{HashError, TransformError},
    CryptographicSuiteInput, ExpandedConfigurationRef,
};
use ssi_json_ld::{AnyJsonLdEnvironment, ContextLoader, JsonLdEnvironment};
use ssi_rdf::{AnyLdEnvironment, Expandable, LdEnvironment};
use ssi_verification_methods::AnyMethod;

use super::AnySuite;

/// Input environment for any cryptographic suite supported by `AnySuite` with
/// a given JSON-LD context loader and sensible defaults for the vocabulary,
/// interpretation and EIP712 type loader.
pub type AnyEnvironmentWithLdLoader<L = ContextLoader> =
    AnyInputContext<JsonLdEnvironment<(), WithGenerator<generator::Blank>, L>>;

/// Input context for any cryptographic suite supported by `AnySuite`.
pub struct AnyInputContext<E = JsonLdEnvironment, L = ()> {
    /// The Linked-Data context used to interpret RDF terms.
    pub ld: E,

    /// Remote resources loader.
    ///
    /// Used for instance with the `EthereumEip712Signature2021` suite to load
    /// EIP712 type definitions from the URI given in the proof options.
    pub loader: L,
}

impl<E, L> AnyInputContext<E, L> {
    pub fn new(ld: E, loader: L) -> Self {
        Self { ld, loader }
    }
}

impl<L> AnyInputContext<JsonLdEnvironment<(), WithGenerator<generator::Blank>, L>> {
    pub fn from_ld_context_loader(loader: L) -> Self {
        Self {
            ld: JsonLdEnvironment::from_loader(loader),
            loader: (),
        }
    }
}

impl<E: AnyLdEnvironment, L> AnyLdEnvironment for AnyInputContext<E, L> {
    type Vocabulary = E::Vocabulary;
    type Interpretation = E::Interpretation;

    fn as_ld_environment_mut(
        &mut self,
    ) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation> {
        self.ld.as_ld_environment_mut()
    }
}

impl<E: AnyJsonLdEnvironment, L> AnyJsonLdEnvironment for AnyInputContext<E, L>
where
    E::Vocabulary: IriVocabulary,
{
    type Loader = E::Loader;

    fn as_json_ld_environment_mut(
        &mut self,
    ) -> ssi_json_ld::JsonLdEnvironment<
        &mut Self::Vocabulary,
        &mut Self::Interpretation,
        &mut Self::Loader,
    > {
        self.ld.as_json_ld_environment_mut()
    }
}

impl<E> AnyInputContext<E> {
    pub fn from_environment(ld: E) -> Self {
        Self { ld, loader: () }
    }
}

impl<I, V> From<LdEnvironment<V, I>> for AnyInputContext<LdEnvironment<V, I>> {
    fn from(value: LdEnvironment<V, I>) -> Self {
        AnyInputContext {
            ld: value,
            loader: (),
        }
    }
}

impl Default
    for AnyInputContext<
        JsonLdEnvironment<(), interpretation::WithGenerator<rdf_types::generator::Blank>>,
        (),
    >
{
    fn default() -> Self {
        Self {
            ld: JsonLdEnvironment {
                vocabulary: (),
                interpretation: interpretation::WithGenerator::new(
                    (),
                    rdf_types::generator::Blank::new(),
                ),
                loader: ContextLoader::default(),
            },
            loader: (),
        }
    }
}

impl<
        V: rdf_types::Vocabulary,
        I: rdf_types::Interpretation,
        E,
        #[cfg(feature = "eip712")] L: ssi_data_integrity_suites::eip712::TypesProvider,
        #[cfg(not(feature = "eip712"))] L,
        T,
    > CryptographicSuiteInput<T, AnyInputContext<E, L>> for AnySuite
where
    E: AnyLdEnvironment<Vocabulary = V, Interpretation = I>,
    I: rdf_types::interpretation::InterpretationMut<V>
        + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    T: serde::Serialize + Expandable<E>,
    T::Expanded: linked_data::LinkedData<I, V>,
{
    // type Transform<'t> = Transform<'t, L> where T: 't, AnyInputContext<E, L>: 't;

    /// Transformation algorithm.
    #[allow(unused)]
    async fn transform<'t, 'c: 't>(
        &'t self,
        data: &'t T,
        context: &'t mut AnyInputContext<E, L>,
        params: ExpandedConfigurationRef<'c, AnyMethod, AnySuiteOptions>,
    ) -> Result<Self::Transformed, TransformError>
    where
        AnyInputContext<E, L>: 't,
    {
        macro_rules! ld_crypto_suites {
            {
                $(
                    $(#[cfg($($t:tt)*)])?
                    $field_name:ident: $name:ident
                ),*
            } => {
                match self {
                    $(
                        $(#[cfg($($t)*)])?
                        Self::$name => {
							match params.try_cast_verification_method() {
								Ok(params) => {
									Ok(ssi_data_integrity_suites::$name.transform(
										data,
										&mut context.ld,
										params
									).await?.into())
								}
								Err(e) => {
                                    Err(e.into())
                                }
							}
                        },
                    )*
					#[cfg(feature = "tezos")]
					Self::TezosJcsSignature2021 => {
						match params.try_cast_verification_method() {
							Ok(params) => {
								Ok(ssi_data_integrity_suites::TezosJcsSignature2021.transform(
									data,
									&mut (),
									params
								).await?.into())
							}
							Err(e) => Err(e.into())
						}
					}
					#[cfg(all(feature = "w3c", feature = "eip712"))]
					Self::EthereumEip712Signature2021 => {
						match params.try_cast_verification_method() {
							Ok(params) => {
								Ok(ssi_data_integrity_suites::EthereumEip712Signature2021.transform(
									data,
									&mut context.loader,
									params
								).await?.into())
							}
							Err(e) => Err(e.into())
						}
					}
                    #[cfg(all(feature = "w3c", feature = "eip712"))]
					Self::EthereumEip712Signature2021v0_1 => {
						match params.try_cast_verification_method() {
							Ok(params) => {
								Ok(ssi_data_integrity_suites::EthereumEip712Signature2021v0_1.transform(
									data,
									&mut context.loader,
									params
								).await?.into())
							}
							Err(e) => Err(e.into())
						}
					},
                    #[allow(unreachable_patterns)]
                    _ => unreachable!()
                }
            }
        }

        ld_crypto_suites! {
            #[cfg(all(feature = "w3c", feature = "rsa"))]
            rsa_signature_2018: RsaSignature2018,
            #[cfg(all(feature = "w3c", feature = "ed25519"))]
            ed25519_signature_2018: Ed25519Signature2018,
            #[cfg(all(feature = "w3c", feature = "ed25519"))]
            ed25519_signature_2020: Ed25519Signature2020,
            #[cfg(all(feature = "w3c", feature = "ed25519"))]
            ed_dsa_2022: EdDsa2022,
            #[cfg(all(feature = "w3c", feature = "secp256k1"))]
            ecdsa_secp_256k1_signature2019: EcdsaSecp256k1Signature2019,
            #[cfg(all(feature = "w3c", feature = "secp256r1"))]
            ecdsa_secp_256r1_signature2019: EcdsaSecp256r1Signature2019,
            #[cfg(feature = "w3c")]
            json_web_signature_2020: JsonWebSignature2020,
            #[cfg(all(feature = "dif", feature = "secp256k1"))]
            ecdsa_secp256k1_recovery_signature2020: EcdsaSecp256k1RecoverySignature2020,
            #[cfg(feature = "solana")]
            solana_signature_2021: SolanaSignature2021,
            #[cfg(feature = "aleo")]
            aleo_signature_2021: AleoSignature2021,
            #[cfg(all(feature = "tezos", feature = "ed25519"))]
            ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021: Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            #[cfg(all(feature = "tezos", feature = "secp256r1"))]
            p256_blake2b_digest_size20_base58_check_encoded_signature_2021: P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            #[cfg(feature = "tezos")]
            tezos_signature_2021: TezosSignature2021,
            #[cfg(all(feature = "ethereum", feature = "eip712"))]
            eip712_signature_2021: Eip712Signature2021,
            #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
            ethereum_personal_signature_2021: EthereumPersonalSignature2021,
            #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
            ethereum_personal_signature_2021_v0_1: EthereumPersonalSignature2021v0_1
        }
    }
}

#[derive(Debug, Clone)]
pub enum Transformed {
    String(String),
    JsonObject(json_syntax::Object),
    Eip712(ssi_eip712::TypedData),
}

impl From<String> for Transformed {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<json_syntax::Object> for Transformed {
    fn from(value: json_syntax::Object) -> Self {
        Self::JsonObject(value)
    }
}

impl From<ssi_eip712::TypedData> for Transformed {
    fn from(value: ssi_eip712::TypedData) -> Self {
        Self::Eip712(value)
    }
}

impl TryFrom<Transformed> for String {
    type Error = HashError;

    fn try_from(value: Transformed) -> Result<Self, Self::Error> {
        match value {
            Transformed::String(s) => Ok(s),
            _ => Err(HashError::InvalidTransformedInput),
        }
    }
}

impl TryFrom<Transformed> for json_syntax::Object {
    type Error = HashError;

    fn try_from(value: Transformed) -> Result<Self, Self::Error> {
        match value {
            Transformed::JsonObject(o) => Ok(o),
            _ => Err(HashError::InvalidTransformedInput),
        }
    }
}

impl TryFrom<Transformed> for ssi_eip712::TypedData {
    type Error = HashError;

    fn try_from(value: Transformed) -> Result<Self, Self::Error> {
        match value {
            Transformed::Eip712(d) => Ok(d),
            _ => Err(HashError::InvalidTransformedInput),
        }
    }
}
