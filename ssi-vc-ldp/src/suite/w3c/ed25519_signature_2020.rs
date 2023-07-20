//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use rdf_types::{IriVocabulary, LanguageTagVocabulary, ReverseTermInterpretation, Vocabulary};
use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_rdf::{DatasetWithEntryPoint, IntoNQuads};
use ssi_vc::ProofValidity;
use static_iref::iri;

use crate::{verification, CryptographicSuite, Proof, ProofConfiguration, ProofOptions};

use crate::suite::{
    CryptographicSuiteInput, SigningParameters, TransformationOptions, VerificationParameters,
};

pub use verification::method::Ed25519VerificationKey2020;

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2020;

impl Ed25519Signature2020 {
    pub fn proof_configuration(options: &ProofOptions<Self>) -> ProofConfiguration<Self> {
        ProofConfiguration {
            type_: options.type_,
            created: options.created,
            verification_method: options.verification_method.clone(),
            proof_purpose: options.proof_purpose,
        }
    }
}

impl<'a, V, I> CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>> for Ed25519Signature2020
where
    V: Vocabulary<
        Type = rdf_types::literal::Type<
            <V as IriVocabulary>::Iri,
            <V as LanguageTagVocabulary>::LanguageTag,
        >,
        Value = String,
    >,
    I: ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
{
    /// Transformation algorithm.
    fn transform(
        &self,
        data: DatasetWithEntryPoint<'a, V, I>,
        _options: TransformationOptions<Self>,
    ) -> Self::Transformed {
        data.canonical_form()
    }
}

#[async_trait::async_trait]
impl CryptographicSuite for Ed25519Signature2020 {
    type TransformationParameters = TransformationOptions<Self>;
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self>;

    type SigningParameters = ProofOptions<Self>;

    type VerificationParameters = ProofOptions<Self>;

    type VerificationMethod = verification::MethodReferenceOrOwned<Ed25519VerificationKey2020>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2020")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(&self, data: String, proof_configuration: ProofConfiguration<Self>) -> Self::Hashed {
        let transformed_document_hash = ssi_crypto::hashes::sha256::sha256(data.as_bytes());
        let proof_config_hash: [u8; 32] = ssi_crypto::hashes::sha256::sha256(
            proof_configuration.quads().into_nquads().as_bytes(),
        );
        let mut hash_data = [0u8; 64];
        hash_data[..32].copy_from_slice(&transformed_document_hash);
        hash_data[32..].copy_from_slice(&proof_config_hash);
        hash_data
    }

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod>,
        options: ProofOptions<Self>,
    ) -> Result<Proof<Self>, SignatureError> {
        let sig = signer.sign(&options.verification_method, data)?;
        let sig_multibase = ssi_vc::schema::sec::layout::Multibase::new(multibase::encode(
            multibase::Base::Base58Btc,
            sig,
        ));
        Ok(Proof::from_options(options, sig_multibase.into()))
    }

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: &Proof<Self>,
    ) -> Result<ProofValidity, VerificationError> {
        let proof_value = proof
            .proof_value
            .as_multibase()
            .ok_or(VerificationError::InvalidProof)?;
        let signature = multibase::decode(proof_value.as_str())
            .map_err(|_| VerificationError::InvalidProof)?
            .1;
        Ok(verifier
            .verify(
                &proof.verification_method,
                proof.proof_purpose,
                data,
                &signature,
            )
            .await?
            .into())
    }
}

impl
    SigningParameters<
        TransformationOptions<Ed25519Signature2020>,
        ProofConfiguration<Ed25519Signature2020>,
        ProofOptions<Ed25519Signature2020>,
    > for ProofOptions<Ed25519Signature2020>
{
    fn transformation_parameters(&self) -> TransformationOptions<Ed25519Signature2020> {
        TransformationOptions { type_: self.type_ }
    }

    fn hash_parameters(&self) -> ProofConfiguration<Ed25519Signature2020> {
        Ed25519Signature2020::proof_configuration(self)
    }

    fn into_proof_parameters(self) -> ProofOptions<Ed25519Signature2020> {
        self
    }
}

impl
    VerificationParameters<
        TransformationOptions<Ed25519Signature2020>,
        ProofConfiguration<Ed25519Signature2020>,
    > for ProofOptions<Ed25519Signature2020>
{
    fn transformation_parameters(&self) -> TransformationOptions<Ed25519Signature2020> {
        TransformationOptions { type_: self.type_ }
    }

    fn into_hash_parameters(self) -> ProofConfiguration<Ed25519Signature2020> {
        Ed25519Signature2020::proof_configuration(&self)
    }
}
