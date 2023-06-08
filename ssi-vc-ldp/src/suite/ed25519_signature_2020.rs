use std::marker::PhantomData;

use iref::IriBuf;
use ssi_crypto::{Algorithm, Signer, Verifier, VerifierProvider};
use ssi_rdf::IntoNQuads;
use ssi_vc::ProofValidity;
use treeldr_rust_prelude::static_iref::iri;

use crate::{
    LinkedDataCredential, Proof, ProofConfiguration, ProofOptions, SignParams, SignerProvider,
};

use super::{TransformationOptions, VerificationMethod, VerificationParameters};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    UnsupportedAlgorithm(ssi_crypto::UnsupportedAlgorithm),

    #[error("unknown verification method")]
    UnknownVerificationMethod,

    #[error("proof decoding failed")]
    ProofDecodingFailed,
}

impl From<ssi_crypto::UnsupportedAlgorithm> for Error {
    fn from(value: ssi_crypto::UnsupportedAlgorithm) -> Self {
        Self::UnsupportedAlgorithm(value)
    }
}

/// Ed25519Signature2020 signature type.
pub struct Ed25519Signature2020<M = IriBuf>(PhantomData<M>);

impl<M> Default for Ed25519Signature2020<M> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<M> Clone for Ed25519Signature2020<M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M> Copy for Ed25519Signature2020<M> {}

impl<M> Ed25519Signature2020<M> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn proof_configuration(options: &ProofOptions<Self, M>) -> ProofConfiguration<Self, M>
    where
        M: Clone,
    {
        ProofConfiguration {
            type_: options.type_,
            created: options.created,
            verification_method: options.verification_method.clone(),
            proof_purpose: options.proof_purpose,
        }
    }
}

impl<M> super::Type for Ed25519Signature2020<M> {
    fn iri(&self) -> iref::Iri {
        //iri!("https://w3id.org/security#Ed25519Signature2020")
        iri!("https://w3id.org/security#DataIntegrityProof")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        Some("eddsa-2022")
    }
}

impl<M: VerificationMethod, C> super::LinkedDataCryptographicSuite<M, C>
    for Ed25519Signature2020<M>
{
    /// Transformation algorithm.
    fn transform<T: LinkedDataCredential<C>>(
        &self,
        context: &mut C,
        data: &T,
        _options: TransformationOptions<Self>,
    ) -> Result<Self::Transformed, Self::Error> {
        Ok(data.canonical_form(context).into_iter().into_nquads())
    }
}

impl<M: Clone + VerificationMethod> super::VerifiableCryptographicSuite<M>
    for Ed25519Signature2020<M>
{
    type VerificationParameters = ProofOptions<Self, M>;
}

impl<M: VerificationMethod> super::CryptographicSuite<M> for Ed25519Signature2020<M> {
    type Error = Error;

    type TransformationParameters = TransformationOptions<Self>;
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self, M>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self, M>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self, M>,
    ) -> Result<Self::Hashed, Self::Error> {
        let transformed_document_hash = ssi_crypto::hashes::sha256::sha256(data.as_bytes());
        let proof_config_hash: [u8; 32] = ssi_crypto::hashes::sha256::sha256(
            proof_configuration.quads().into_nquads().as_bytes(),
        );
        let mut hash_data = [0u8; 64];
        hash_data[..32].copy_from_slice(&transformed_document_hash);
        hash_data[32..].copy_from_slice(&proof_config_hash);
        Ok(hash_data)
    }

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: &impl SignerProvider<M>,
        options: ProofOptions<Self, M>,
    ) -> Result<Proof<Self, M>, Self::Error> {
        let signer = signer_provider.get_signer(&options.verification_method);
        let sig = signer.sign(Algorithm::EdDSA, &data)?;
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);

        Ok(Proof::from_options(options, sig_multibase))
    }

    fn verify_proof(
        &self,
        data: Self::Hashed,
        verifier_provider: &impl VerifierProvider<M>,
        proof: &Proof<Self, M>,
    ) -> Result<ProofValidity, Self::Error> {
        let verifier = verifier_provider
            .get_verifier(&proof.verification_method)
            .ok_or(Error::UnknownVerificationMethod)?;
        let proof_bytes = multibase::decode(&proof.proof_value)
            .map_err(|_| Error::ProofDecodingFailed)?
            .1;
        Ok(verifier
            .verify(Algorithm::EdDSA, &data, &proof_bytes)?
            .into())
    }
}

impl<M: Clone + VerificationMethod> SignParams<M, Ed25519Signature2020<M>>
    for ProofOptions<Ed25519Signature2020<M>, M>
{
    fn transform_params(
        &self,
    ) -> <Ed25519Signature2020<M> as super::CryptographicSuite<M>>::TransformationParameters {
        TransformationOptions { type_: self.type_ }
    }

    fn hash_params(
        &self,
    ) -> <Ed25519Signature2020<M> as super::CryptographicSuite<M>>::HashParameters {
        Ed25519Signature2020::proof_configuration(self)
    }

    fn into_proof_params(
        self,
    ) -> <Ed25519Signature2020<M> as super::CryptographicSuite<M>>::ProofParameters {
        self
    }
}

impl<M: Clone + VerificationMethod>
    VerificationParameters<
        TransformationOptions<Ed25519Signature2020<M>>,
        ProofConfiguration<Ed25519Signature2020<M>, M>,
    > for ProofOptions<Ed25519Signature2020<M>, M>
{
    fn transformation_parameters(
        &self,
    ) -> <Ed25519Signature2020<M> as super::CryptographicSuite<M>>::TransformationParameters {
        TransformationOptions { type_: self.type_ }
    }

    fn into_hash_parameters(
        self,
    ) -> <Ed25519Signature2020<M> as super::CryptographicSuite<M>>::HashParameters {
        Ed25519Signature2020::proof_configuration(&self)
    }
}
