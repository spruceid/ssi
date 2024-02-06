//! EIP-712 Signature 2021 implementation.
use rdf_types::Quad;
use ssi_crypto::MessageSigner;
use ssi_rdf::NQuadsStatement;
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020, ecdsa_secp_256k1_verification_key_2019,
    verification_method_union, EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    Eip712Method2021, SignatureError, VerificationError,
};
use static_iref::iri;

use crate::{
    eip712::{Eip712Signature, Eip712SignatureRef},
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, LinkedDataInput, ProofConfigurationRef,
};

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
    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Eip712Signature2021");
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        Eip712Method2021,
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn algorithm(&self) -> ssi_jwk::algorithm::AnyESKeccakK {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => {
                ssi_jwk::algorithm::AnyESKeccakK::ESKeccakK
            }
            Self::Eip712Method2021(_) | Self::EcdsaSecp256k1RecoveryMethod2020(_) => {
                ssi_jwk::algorithm::AnyESKeccakK::ESKeccakKR
            }
        }
    }

    pub fn verify_bytes(
        &self,
        signing_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
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

impl CryptographicSuite for Eip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 66];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: ssi_eip712::TypedData,
        _proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        data.encode()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl<'a, V: rdf_types::Vocabulary, I: rdf_types::Interpretation, T>
    CryptographicSuiteInput<T, LinkedDataInput<I, V>> for Eip712Signature2021
where
    I: rdf_types::interpretation::InterpretationMut<V>
        + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    T: linked_data::LinkedData<I, V>,
{
    type Transform<'t> = std::future::Ready<Result<Self::Transformed, TransformError>> where T: 't, LinkedDataInput<I, V>: 't;

    /// Transformation algorithm.
    fn transform<'t, 'c: 't>(
        &'t self,
        data: &'t T,
        context: &'t mut LinkedDataInput<I, V>,
        options: ProofConfigurationRef<'c, VerificationMethod>,
    ) -> Self::Transform<'t>
    where
        LinkedDataInput<I, V>: 't,
    {
        std::future::ready(transform(self, data, context, options))
    }
}

fn transform<V: rdf_types::Vocabulary, I: rdf_types::Interpretation, T>(
    suite: &Eip712Signature2021,
    data: &T,
    context: &mut LinkedDataInput<I, V>,
    options: ProofConfigurationRef<VerificationMethod>,
) -> Result<ssi_eip712::TypedData, TransformError>
where
    I: rdf_types::interpretation::InterpretationMut<V>
        + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    T: linked_data::LinkedData<I, V>,
{
    let document_quads = context.into_quads(data)?;
    let document_quads: Vec<_> =
        ssi_rdf::urdna2015::normalize(document_quads.iter().map(|quad| quad.as_quad_ref()))
            .collect();
    let proof_quads = options.quads(suite);
    Ok(new_ldp_siging_request(document_quads, proof_quads))
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
    mut document: Vec<Quad>,
    mut proof_configuration: Vec<Quad>,
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

    fn encode_statement(Quad(s, p, o, g): Quad) -> Value {
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

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Options = ();

    type Signature = Eip712Signature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        method: <VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        Eip712Signature::sign(bytes, signer, method.algorithm()).await
    }

    fn verify(
        &self,
        _options: (),
        signature: Eip712SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let signature_bytes = signature.decode()?;
        method.verify_bytes(bytes, &signature_bytes)
    }
}
