//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use ssi_verification_methods::{
    verification_method_union, EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    JsonWebKey2020,
};
use static_iref::iri;

use crate::{
    suite::{Eip712Signature, Eip712SignatureRef, HashError},
    CryptographicSuite, CryptographicSuiteInput, ProofConfiguration, ProofConfigurationRef,
};

/// Ethereum EIP-712 Signature 2021.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
///
/// # Input
///
/// This suites accepts a [EIP `TypedData`][1] object, with or without a `types`
/// property, represented by the [`Input`] type.
///
/// [1]: <https://eips.ethereum.org/EIPS/eip-712>
///
/// # Transformation algorithm
///
/// If no `types` property is bound to the input `TypedData`, one is generated
/// according to the [Types Generation algorithm][2].
///
/// [2]: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#types-generation>
///
/// # Hashing algorithm
///
/// The transformed input is hashed using the `Keccak-256` algorithm.
///
/// # Signature algorithm
///
/// The hashed input is signed using the `ECDSA K-256` signature algorithm.
///
/// # Verification methods
///
/// The following verification methods can be used to sign/verify a credential
/// with this suite:
/// - [`EcdsaSecp256k1VerificationKey2019`],
/// - [`EcdsaSecp256k1RecoveryMethod2020`],
/// - [`JsonWebKey2020`]
///
/// # Linked-Data support
///
/// This suite is not a Linked-Data cryptographic suite.
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021; // TODO add LD support

pub struct Options {
    /// If true (by default), the signature metadata will include the
    /// `eip712` property.
    pub embed: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { embed: true }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub types: Option<ssi_eip712::Types>,
    pub primary_type: Option<ssi_eip712::StructName>,
    pub domain: Option<ssi_eip712::Value>,
    pub message: ssi_eip712::Struct,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidInput {
    #[error(transparent)]
    TypeGenerationFailed(#[from] ssi_eip712::TypesGenerationError),

    #[error("invalid message")]
    InvalidMessage,

    #[error("found a `proof` value in the message")]
    FoundProofValue,
}

impl Input {
    pub fn try_into_typed_data<M: serde::Serialize>(
        mut self,
        proof_configuration: ProofConfiguration<M>,
    ) -> Result<ssi_eip712::TypedData, InvalidInput> {
        let domain = self.domain.unwrap_or_else(Self::default_domain);
        let primary_type = self.primary_type.unwrap_or_else(Self::default_primary_type);

        self.message.insert(
            "proof".to_string(),
            ssi_eip712::to_value(&proof_configuration).unwrap(),
        );

        let message = ssi_eip712::Value::Struct(self.message);

        let types = match self.types {
            Some(types) => types,
            None => ssi_eip712::Types::generate(
                &message,
                primary_type.clone(),
                Self::default_domain_type(),
            )?,
        };

        Ok(ssi_eip712::TypedData {
            types,
            primary_type,
            domain,
            message,
        })
    }

    pub fn default_domain() -> ssi_eip712::Value {
        ssi_eip712::Value::Struct(
            [(
                "name".to_string(),
                ssi_eip712::Value::String("EthereumEip712Signature2021".to_string()),
            )]
            .into_iter()
            .collect(),
        )
    }

    pub fn default_domain_type() -> ssi_eip712::TypeDefinition {
        ssi_eip712::TypeDefinition::new(vec![ssi_eip712::MemberVariable::new(
            "name".to_string(),
            ssi_eip712::TypeRef::String,
        )])
    }

    pub fn default_primary_type() -> ssi_eip712::StructName {
        "Document".into()
    }
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020,
        JsonWebKey2020
    }
}

impl CryptographicSuite for EthereumEip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 32];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = Options;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#EthereumEip712Signature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    // fn generate_signature_metadata(&self, data: &Self::Transformed, options: &Self::Options) -> Self::SignatureMetadata {
    //     SignatureMetadata {
    //         eip712: options.embed.then(|| Eip712Metadata {
    //             types_or_uri: TypesOrURI::Object(data.types.clone()),
    //             primary_type: data.primary_type.clone(),
    //             domain: data.domain.clone()
    //         })
    //     }
    // }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: ssi_eip712::TypedData,
        _proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        data.hash()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl CryptographicSuiteInput<ssi_eip712::TypedData> for EthereumEip712Signature2021 {
    type TransformError = std::convert::Infallible;

    fn transform(
        &self,
        data: ssi_eip712::TypedData,
        _params: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Transformed, Self::TransformError> {
        // apply options.
        Ok(data)
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Signature = Eip712Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
        &self,
        method: VerificationMethodRef,
        bytes: &[u8],
        signer: &S,
    ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        signature: Eip712SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
