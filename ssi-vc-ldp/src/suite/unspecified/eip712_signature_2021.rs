//! EIP-712 Signature 2021 implementation.
use std::future;

use rdf_types::Quad;
use ssi_crypto::MessageSigner;
use ssi_verification_methods::{
    verification_method_union, EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    Eip712Method2021, SignatureError,
};
use static_iref::iri;

use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ProofConfigurationRef,
    eip712::{Eip712Signature, Eip712SignatureRef}, LinkedDataInput
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
/// The hashed input is signed using the `ECDSA K-256` signature algorithm.
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

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        Eip712Method2021,
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl CryptographicSuite for Eip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 32];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#EthereumEip712Signature2021")
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
        data.hash()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl<'a, V: rdf_types::Vocabulary, I: rdf_types::Interpretation, G, T>
    CryptographicSuiteInput<T, LinkedDataInput<'a, V, I, G>> for Eip712Signature2021
where
    I: rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
        + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    G: rdf_types::Generator<()>,
    T: linked_data::LinkedData<V, I>,
{
    type Transform<'t> = std::future::Ready<Result<Self::Transformed, TransformError>> where T: 't, LinkedDataInput<'a, V, I, G>: 't;

    /// Transformation algorithm.
    fn transform<'t, 'c: 't>(
        &'t self,
        data: &'t T,
        context: LinkedDataInput<'a, V, I, G>,
        options: ProofConfigurationRef<'c, VerificationMethod>,
    ) -> Self::Transform<'t> where LinkedDataInput<'a, V, I, G>: 't {
        std::future::ready(transform(self, data, context, options))
    }
}

fn transform<V: rdf_types::Vocabulary, I: rdf_types::Interpretation, G, T>(
    suite: &Eip712Signature2021,
    data: &T,
    context: LinkedDataInput<V, I, G>,
    options: ProofConfigurationRef<VerificationMethod>,
) -> Result<ssi_eip712::TypedData, TransformError>
where
    I: rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
    + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
    + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    G: rdf_types::Generator<()>,
    T: linked_data::LinkedData<V, I>,
{
    let document_quads = context.into_quads(data)?;
    let document_quads: Vec<_> = ssi_rdf::urdna2015::normalize(document_quads.iter().map(|quad| quad.as_quad_ref())).collect();
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
    document: Vec<Quad>,
    proof_configuration: Vec<Quad>,
) -> ssi_eip712::TypedData {
    use ssi_eip712::{TypeRef, Value};

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

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        _options: (),
        method: VerificationMethodRef,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        signature: Eip712SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, Eip712Method2021, signature::Base58PublicKeyJwkOrMultibase> for &'a Eip712Method2021 {
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         signing_bytes: &[u8],
//         signature: signature::
//     ) -> Result<bool, VerificationError> {
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         let (algorithm, signature_bytes) = ssi_tzkey::decode_tzsig(signature.proof_value)
//             .map_err(|_| VerificationError::InvalidSignature)?;

//         let key = match signature.public_key.map(|k| k.as_jwk()).transpose()? {
//             Some(key) => {
//                 if !self.public_key.matches(&key)? {
//                     return Err(VerificationError::InvalidProof);
//                 }

//                 key
//             }
//             None => match &self.public_key {
//                 PublicKey::Jwk(key) => Cow::Borrowed(key.as_ref()),
//                 _ => return Err(VerificationError::MissingPublicKey),
//             },
//         };

//         Ok(ssi_jws::verify_bytes(algorithm, signing_bytes, &key, &signature_bytes).is_ok())
//     }
// }
