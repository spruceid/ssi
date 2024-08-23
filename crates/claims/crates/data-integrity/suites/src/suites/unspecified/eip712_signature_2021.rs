//! EIP-712 Signature 2021 implementation.
use crate::{
    eip712::{Eip712Hashing, Eip712Signature},
    try_from_type,
};
use rdf_types::{LexicalQuad, Quad};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    suite::{
        standard::{
            SignatureAlgorithm, SignatureAndVerificationAlgorithm, TransformationAlgorithm,
            TransformationError, TypedTransformationAlgorithm, VerificationAlgorithm,
        },
        AddProofContext,
    },
    CryptographicSuite, ProofConfigurationRef, StandardCryptographicSuite, TypeRef,
};
use ssi_json_ld::{Expandable, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::{AnyLdEnvironment, LdEnvironment, NQuadsStatement};
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020, ecdsa_secp_256k1_verification_key_2019,
    verification_method_union, AnyMethod, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, Eip712Method2021, InvalidVerificationMethod, MessageSigner,
};
use static_iref::iri;

lazy_static::lazy_static! {
    pub static ref EIP712VM_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        let context_str = ssi_contexts::EIP712VM;
        serde_json::from_str(context_str).unwrap()
    };
}

#[derive(Default)]
pub struct Eip712VmContext;

impl From<Eip712VmContext> for ssi_json_ld::syntax::Context {
    fn from(_: Eip712VmContext) -> Self {
        ssi_json_ld::syntax::Context::One(EIP712VM_CONTEXT.clone())
    }
}

/// EIP-712 Signature 2021.
///
/// Based on the [Ethereum EIP-712 Signature 2021][1] but working on
/// Linked-Data documents.
///
/// [1]: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
///
/// # Input
///
/// This suites accepts Linked Data documents.
///
/// # Transformation algorithm
///
/// The input document is converted into an RDF dataset and encoded into an
/// a [EIP-712 `TypedData`][1] object.
///
/// [1]: <https://eips.ethereum.org/EIPS/eip-712>
///
/// # Hashing algorithm
///
/// The transformed input is hashed using the `Keccak-256` algorithm.
///
/// # Signature algorithm
///
/// The hashed input is signed using the `ECDSA KeccakK` signature algorithm.
///
/// # Verification methods
///
/// The following verification methods can be used to sign/verify a credential
/// with this suite:
/// - [`Eip712Method2021`]
/// - [`EcdsaSecp256k1VerificationKey2019`],
/// - [`EcdsaSecp256k1RecoveryMethod2020`]
#[derive(Debug, Default, Clone, Copy)]
pub struct Eip712Signature2021;

impl Eip712Signature2021 {
    pub const NAME: &'static str = "Eip712Signature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Eip712Signature2021");
}

impl StandardCryptographicSuite for Eip712Signature2021 {
    type Configuration = AddProofContext<Eip712VmContext>;

    type Transformation = Eip712Transformation;

    type Hashing = Eip712Hashing;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = Eip712SignatureAlgorithm;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(Eip712Signature2021);

pub struct Eip712Transformation;

impl TransformationAlgorithm<Eip712Signature2021> for Eip712Transformation {
    type Output = ssi_eip712::TypedData;
}

impl<T, C> TypedTransformationAlgorithm<Eip712Signature2021, T, C> for Eip712Transformation
where
    T: Expandable + JsonLdNodeObject,
    C: JsonLdLoaderProvider,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, Eip712Signature2021>,
        _verification_method: &VerificationMethod,
        _transformation_options: (),
    ) -> Result<ssi_eip712::TypedData, TransformationError> {
        let mut ld = LdEnvironment::default();

        let expanded = data
            .expand_with(&mut ld, context.loader())
            .await
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        let claims = ld
            .canonical_quads_of(&expanded)
            .map_err(TransformationError::JsonLdDeserialization)?;

        let configuration = proof_configuration
            .expand(context, data)
            .await
            .map_err(TransformationError::ProofConfigurationExpansion)?
            .quads()
            .collect();

        Ok(new_ldp_siging_request(claims, configuration))
    }
}

/// Creates a typed structured data representing a Linked Data signing
/// request.
///
/// # Example
///
/// ```text
/// LDPSigningRequest {
///   document: [
///     ["subject1", "predicate1", "object1", "graph1"],
///     ...
///     ["subjectN", "predicateN", "objectN", "graphN"]
///   ],
///   proof: [
///     ["subject1", "predicate1", "object1", "graph1"],
///     ...
///     ["subjectM", "predicateM", "objectM", "graphM"]
///   ]
/// }
/// ```
pub fn new_ldp_siging_request(
    mut document: Vec<LexicalQuad>,
    mut proof_configuration: Vec<LexicalQuad>,
) -> ssi_eip712::TypedData {
    use ssi_eip712::{TypeRef, Value};

    document.sort_by_cached_key(|x| NQuadsStatement(x).to_string());
    proof_configuration.sort_by_cached_key(|x| NQuadsStatement(x).to_string());

    let types = ssi_eip712::Types {
        eip712_domain: ssi_eip712::TypeDefinition::new(vec![ssi_eip712::MemberVariable {
            name: "name".to_string(),
            type_: TypeRef::String,
        }]),
        types: [(
            "LDPSigningRequest".to_string(),
            ssi_eip712::TypeDefinition::new(vec![
                ssi_eip712::MemberVariable {
                    name: "document".to_string(),
                    type_: TypeRef::Array(Box::new(TypeRef::Array(Box::new(TypeRef::String)))),
                },
                ssi_eip712::MemberVariable {
                    name: "proof".to_string(),
                    type_: TypeRef::Array(Box::new(TypeRef::Array(Box::new(TypeRef::String)))),
                },
            ]),
        )]
        .into_iter()
        .collect(),
    };

    fn encode_statement(Quad(s, p, o, g): LexicalQuad) -> Value {
        use rdf_types::RdfDisplay;

        let mut terms = vec![
            Value::String(s.rdf_display().to_string()),
            Value::String(p.rdf_display().to_string()),
            Value::String(o.rdf_display().to_string()),
        ];

        if let Some(graph_label) = g {
            terms.push(Value::String(graph_label.rdf_display().to_string()));
        }

        Value::Array(terms)
    }

    ssi_eip712::TypedData {
        types,
        primary_type: "LDPSigningRequest".to_string(),
        domain: Value::Struct(
            [(
                "name".to_string(),
                Value::String("Eip712Method2021".to_string()),
            )]
            .into_iter()
            .collect(),
        ),
        message: Value::Struct(
            [
                (
                    "document".to_string(),
                    Value::Array(document.into_iter().map(encode_statement).collect()),
                ),
                (
                    "proof".to_string(),
                    Value::Array(
                        proof_configuration
                            .into_iter()
                            .map(encode_statement)
                            .collect(),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

pub struct Eip712SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for Eip712SignatureAlgorithm {
    type Signature = Eip712Signature;
}

impl<T> SignatureAlgorithm<Eip712Signature2021, T> for Eip712SignatureAlgorithm
where
    T: MessageSigner<ssi_crypto::algorithm::AnyESKeccakK>,
{
    async fn sign(
        verification_method: &<Eip712Signature2021 as CryptographicSuite>::VerificationMethod,
        signer: T,
        prepared_claims: <Eip712Signature2021 as CryptographicSuite>::PreparedClaims,
        _proof_configuration: ProofConfigurationRef<'_, Eip712Signature2021>,
    ) -> Result<Self::Signature, SignatureError> {
        Eip712Signature::sign(
            prepared_claims.as_slice(),
            signer,
            verification_method.algorithm(),
        )
        .await
    }
}

impl VerificationAlgorithm<Eip712Signature2021> for Eip712SignatureAlgorithm {
    fn verify(
        method: &<Eip712Signature2021 as CryptographicSuite>::VerificationMethod,
        prepared_claims: <Eip712Signature2021 as CryptographicSuite>::PreparedClaims,
        proof: ssi_data_integrity_core::ProofRef<Eip712Signature2021>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature_bytes = proof.signature.decode()?;
        method
            .verify_bytes(prepared_claims.as_slice(), &signature_bytes)
            .map(Into::into)
    }
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodType {
        Eip712Method2021,
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl VerificationMethod {
    pub fn algorithm(&self) -> ssi_crypto::algorithm::AnyESKeccakK {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => {
                ssi_crypto::algorithm::AnyESKeccakK::ESKeccakK
            }
            Self::Eip712Method2021(_) | Self::EcdsaSecp256k1RecoveryMethod2020(_) => {
                ssi_crypto::algorithm::AnyESKeccakK::ESKeccakKR
            }
        }
    }

    pub fn verify_bytes(
        &self,
        signing_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        match self {
            Self::Eip712Method2021(m) => m.verify_bytes(signing_bytes, signature_bytes),
            Self::EcdsaSecp256k1VerificationKey2019(m) => m.verify_bytes(
                signing_bytes,
                signature_bytes,
                ecdsa_secp_256k1_verification_key_2019::DigestFunction::Keccack,
            ),
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => m.verify_bytes(
                signing_bytes,
                signature_bytes,
                ecdsa_secp_256k1_recovery_method_2020::DigestFunction::Keccack,
            ),
        }
    }
}

impl TryFrom<AnyMethod> for VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            AnyMethod::Eip712Method2021(m) => Ok(Self::Eip712Method2021(m)),
            other => Err(InvalidVerificationMethod::UnsupportedMethodType(
                other.type_().name().to_owned(),
            )),
        }
    }
}

impl From<VerificationMethod> for AnyMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Self::EcdsaSecp256k1VerificationKey2019(m)
            }
            VerificationMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Self::EcdsaSecp256k1RecoveryMethod2020(m)
            }
            VerificationMethod::Eip712Method2021(m) => Self::Eip712Method2021(m),
        }
    }
}
