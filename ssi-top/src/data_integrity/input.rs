use std::{future::Future, pin::Pin, task};

use super::AnySuiteOptions;
use pin_project::pin_project;
use rdf_types::interpretation;
use ssi_vc_ldp::{
    eip712::TypesProvider,
    suite::{HashError, TransformError},
    CryptographicSuiteInput, LinkedDataInput, ProofConfigurationRef,
};

use crate::AnyMethod;
use super::AnySuite;

type JsonObject = serde_json::Map<String, serde_json::Value>;

/// Input context for any cryptographic suite supported by `AnySuite`.
pub struct AnyInputContext<I, V, L = ()> {
    /// The Linked-Data context used to interpret RDF terms.
    pub ld: LinkedDataInput<I, V>,

    /// Remote resources loader.
    ///
    /// Used for instance with the `EthereumEip712Signature2021` suite to load
    /// EIP712 type definitions from the URI given in the proof options.
    pub loader: L,
}

impl<'a, I, V> From<LinkedDataInput<I, V>> for AnyInputContext<I, V> {
    fn from(value: LinkedDataInput<I, V>) -> Self {
        AnyInputContext {
            ld: value,
            loader: (),
        }
    }
}

impl Default
    for AnyInputContext<interpretation::WithGenerator<rdf_types::generator::Blank>, (), ()>
{
    fn default() -> Self {
        Self {
            ld: LinkedDataInput {
                vocabulary: (),
                interpretation: interpretation::WithGenerator::new(
                    (),
                    rdf_types::generator::Blank::new(),
                ),
            },
            loader: (),
        }
    }
}

#[pin_project(project = TransformProj)]
pub enum Transform<'a, L: TypesProvider> {
    Error(Option<TransformError>),
    String(#[pin] std::future::Ready<Result<String, TransformError>>),
    JsonObject(#[pin] std::future::Ready<Result<JsonObject, TransformError>>),
    Eip712(#[pin] std::future::Ready<Result<ssi_eip712::TypedData, TransformError>>),

    #[cfg(feature = "w3c")]
    EthereumEip712Signature2021(
        #[pin] ssi_vc_ldp::suite::ethereum_eip712_signature_2021::Transform<'a, L>,
    ),
}

impl<'a, L: TypesProvider> From<std::future::Ready<Result<String, TransformError>>>
    for Transform<'a, L>
{
    fn from(value: std::future::Ready<Result<String, TransformError>>) -> Self {
        Self::String(value)
    }
}

impl<'a, L: TypesProvider> From<std::future::Ready<Result<JsonObject, TransformError>>>
    for Transform<'a, L>
{
    fn from(value: std::future::Ready<Result<JsonObject, TransformError>>) -> Self {
        Self::JsonObject(value)
    }
}

impl<'a, L: TypesProvider> From<std::future::Ready<Result<ssi_eip712::TypedData, TransformError>>>
    for Transform<'a, L>
{
    fn from(value: std::future::Ready<Result<ssi_eip712::TypedData, TransformError>>) -> Self {
        Self::Eip712(value)
    }
}

impl<'a, L: TypesProvider> Future for Transform<'a, L> {
    type Output = Result<Transformed, TransformError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            TransformProj::Error(e) => task::Poll::Ready(Err(e.take().unwrap())),
            TransformProj::String(f) => f.poll(cx).map(|r| r.map(Transformed::String)),
            TransformProj::JsonObject(f) => f.poll(cx).map(|r| r.map(Transformed::JsonObject)),
            TransformProj::Eip712(f) => f.poll(cx).map(|r| r.map(Transformed::Eip712)),
            TransformProj::EthereumEip712Signature2021(f) => {
                f.poll(cx).map(|r| r.map(Transformed::Eip712))
            }
        }
    }
}

impl<V: rdf_types::Vocabulary, I: rdf_types::Interpretation, L, T>
    CryptographicSuiteInput<T, AnyInputContext<I, V, L>> for AnySuite
where
    I: rdf_types::interpretation::InterpretationMut<V>
        + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    T: serde::Serialize + linked_data::LinkedData<I, V>,
    L: ssi_vc_ldp::eip712::TypesProvider,
{
    type Transform<'t> = Transform<'t, L> where T: 't, AnyInputContext<I, V, L>: 't;

    /// Transformation algorithm.
    fn transform<'t, 'c: 't>(
        &'t self,
        data: &'t T,
        context: AnyInputContext<I, V, L>,
        params: ProofConfigurationRef<'c, AnyMethod, AnySuiteOptions>,
    ) -> Transform<'t, L>
    where
        AnyInputContext<I, V, L>: 't,
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
                            eprintln!("vm: {params:?}");
							match params.try_cast_verification_method() {
								Ok(params) => {
									ssi_vc_ldp::suite::$name.transform(
										data,
										context.ld,
										params
									).into()
								}
								Err(e) => {
                                    eprintln!("invalid verification method: {e:?}");
                                    Transform::Error(Some(e.into()))
                                }
							}
                        },
                    )*
					#[cfg(feature = "tezos")]
					Self::TezosJcsSignature2021 => {
						match params.try_cast_verification_method() {
							Ok(params) => {
								ssi_vc_ldp::suite::TezosJcsSignature2021.transform(
									data,
									(),
									params
								).into()
							}
							Err(e) => Transform::Error(Some(e.into()))
						}
					}
					#[cfg(feature = "w3c")]
					Self::EthereumEip712Signature2021 | Self::EthereumEip712Signature2021v0_1 => {
						match params.try_cast_verification_method() {
							Ok(params) => {
								Transform::EthereumEip712Signature2021(ssi_vc_ldp::suite::EthereumEip712Signature2021.transform(
									data,
									context.loader,
									params
								))
							}
							Err(e) => Transform::Error(Some(e.into()))
						}
					}
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
            #[cfg(feature = "tezos")]
            ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021: Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            #[cfg(feature = "tezos")]
            p256_blake2b_digest_size20_base58_check_encoded_signature_2021: P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            // #[cfg(feature = "tezos")]
            // tezos_jcs_signature_2021: TezosJcsSignature2021,
            #[cfg(feature = "tezos")]
            tezos_signature_2021: TezosSignature2021,
            #[cfg(feature = "eip712")]
            eip712_signature_2021: Eip712Signature2021,
            ethereum_personal_signature_2021: EthereumPersonalSignature2021,
            ethereum_personal_signature_2021_v0_1: EthereumPersonalSignature2021v0_1
            // ethereum_eip712_signature_2021: EthereumEip712Signature2021
        }
    }
}

#[derive(Debug, Clone)]
pub enum Transformed {
    String(String),
    JsonObject(JsonObject),
    Eip712(ssi_eip712::TypedData),
}

impl From<String> for Transformed {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<JsonObject> for Transformed {
    fn from(value: JsonObject) -> Self {
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

impl TryFrom<Transformed> for JsonObject {
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
