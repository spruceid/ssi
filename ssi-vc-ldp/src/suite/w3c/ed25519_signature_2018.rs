use rdf_types::{IriVocabulary, LanguageTagVocabulary, ReverseTermInterpretation, Vocabulary};
use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_rdf::{DatasetWithEntryPoint, IntoNQuads};
use ssi_vc::ProofValidity;
use ssi_verification_methods::{ReferenceOrOwned, VerificationMethod};
use static_iref::iri;

use crate::{verification, CryptographicSuite, Proof, ProofConfiguration, ProofOptions};

use crate::suite::{
    CryptographicSuiteInput, SigningParameters, TransformationOptions, VerificationParameters,
};

pub use verification::method::Ed25519VerificationKey2018;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl Ed25519Signature2018 {
    pub fn proof_configuration(options: &ProofOptions<Self>) -> ProofConfiguration<Self> {
        ProofConfiguration {
            type_: options.type_,
            created: options.created,
            verification_method: options.verification_method.clone(),
            proof_purpose: options.proof_purpose,
        }
    }
}

impl<'a, V, I> CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>> for Ed25519Signature2018
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
impl CryptographicSuite for Ed25519Signature2018 {
    type TransformationParameters = TransformationOptions<Self>;
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self>;

    type SigningParameters = ProofOptions<Self>;

    type VerificationParameters = ProofOptions<Self>;

    type VerificationMethod = verification::MethodReferenceOrOwned<Ed25519VerificationKey2018>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2018")
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
        let signature = signer.sign(&options.verification_method, data)?;

        let key_id = match &options.verification_method {
            ReferenceOrOwned::Owned(key) => key.id(),
            ReferenceOrOwned::Reference(id) => id.iri(),
        };

        let header =
            ssi_jws::Header::new_detached(ssi_jwk::Algorithm::EdDSA, Some(key_id.to_string()));

        let signing_bytes = header.encode_signing_bytes(data);

        let jws =
            ssi_jws::CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature)
                .unwrap();

        Ok(Proof::from_options(options, jws.into()))
    }

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: &Proof<Self>,
    ) -> Result<ProofValidity, VerificationError> {
        let jws = proof
            .proof_value
            .as_jws()
            .ok_or(VerificationError::InvalidProof)?;
        let (_, payload, signature) = jws.decode().map_err(|_| VerificationError::InvalidProof)?;

        if payload.as_ref() != data {
            return Err(VerificationError::InvalidProof);
        }

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
        TransformationOptions<Ed25519Signature2018>,
        ProofConfiguration<Ed25519Signature2018>,
        ProofOptions<Ed25519Signature2018>,
    > for ProofOptions<Ed25519Signature2018>
{
    fn transformation_parameters(&self) -> TransformationOptions<Ed25519Signature2018> {
        TransformationOptions { type_: self.type_ }
    }

    fn hash_parameters(&self) -> ProofConfiguration<Ed25519Signature2018> {
        Ed25519Signature2018::proof_configuration(self)
    }

    fn into_proof_parameters(self) -> ProofOptions<Ed25519Signature2018> {
        self
    }
}

impl
    VerificationParameters<
        TransformationOptions<Ed25519Signature2018>,
        ProofConfiguration<Ed25519Signature2018>,
    > for ProofOptions<Ed25519Signature2018>
{
    fn transformation_parameters(&self) -> TransformationOptions<Ed25519Signature2018> {
        TransformationOptions { type_: self.type_ }
    }

    fn into_hash_parameters(self) -> ProofConfiguration<Ed25519Signature2018> {
        Ed25519Signature2018::proof_configuration(&self)
    }
}
