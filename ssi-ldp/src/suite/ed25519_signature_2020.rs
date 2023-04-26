use std::marker::PhantomData;

use iref::IriBuf;
use ssi_rdf::IntoNQuads;
use treeldr_rust_prelude::static_iref::iri;

use crate::{
    Algorithm, LinkedDataCredential, ProofValidity, SignParams, Signer, SignerProvider, Verifier,
    VerifierProvider, VerifyParams,
};

use super::{
    DataIntegrityProof, ProofConfiguration, ProofOptions, ProofPurpose, TransformationOptions,
    VerificationMethod,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("proof decoding failed")]
    ProofDecodingFailed,
}

/// Ed25519Signature2020 signature type.
pub struct Ed25519Signature2020<M = IriBuf, P = IriBuf>(PhantomData<(M, P)>);

impl<M, P> Default for Ed25519Signature2020<M, P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<M, P> Clone for Ed25519Signature2020<M, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, P> Copy for Ed25519Signature2020<M, P> {}

impl<M, P> Ed25519Signature2020<M, P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn proof_configuration(options: &ProofOptions<Self, M, P>) -> ProofConfiguration<Self, M, P>
    where
        M: Clone,
        P: Clone,
    {
        ProofConfiguration {
            type_: options.type_,
            created: options.created,
            verification_method: options.verification_method.clone(),
            proof_purpose: options.proof_purpose.clone(),
        }
    }
}

impl<M, P> super::Type for Ed25519Signature2020<M, P> {
    fn iri(&self) -> iref::Iri {
        //iri!("https://w3id.org/security#Ed25519Signature2020")
        iri!("https://w3id.org/security#DataIntegrityProof")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        Some("eddsa-2022")
    }
}

impl<M: VerificationMethod, P: ProofPurpose, C> super::LinkedDataCryptographicSuite<M, C>
    for Ed25519Signature2020<M, P>
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

impl<M: VerificationMethod, P: ProofPurpose> super::CryptographicSuite<M>
    for Ed25519Signature2020<M, P>
{
    type Error = Error;

    type TransformationParameters = TransformationOptions<Self>;
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self, M, P>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self, M, P>;
    type Proof = DataIntegrityProof<Self, M, P>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self, M, P>,
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
        options: ProofOptions<Self, M, P>,
    ) -> Result<Self::Proof, Self::Error> {
        let signer = signer_provider.get_signer(&options.verification_method);
        let sig = signer.sign(Algorithm::EdDSA, &data);
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);

        Ok(DataIntegrityProof::from_options(options, sig_multibase))
    }

    fn verify_proof(
        &self,
        data: Self::Hashed,
        verifier_provider: &impl VerifierProvider<M>,
        proof: &Self::Proof,
    ) -> Result<ProofValidity, Self::Error> {
        let verifier = verifier_provider.get_verifier(&proof.verification_method);
        let proof_bytes = multibase::decode(&proof.proof_value)
            .map_err(|_| Error::ProofDecodingFailed)?
            .1;
        Ok(verifier
            .verify(Algorithm::EdDSA, &data, &proof_bytes)
            .into())
    }
}

impl<M: Clone + VerificationMethod, P: Clone + ProofPurpose>
    SignParams<M, Ed25519Signature2020<M, P>> for ProofOptions<Ed25519Signature2020<M, P>, M, P>
{
    fn transform_params(
        &self,
    ) -> <Ed25519Signature2020<M, P> as super::CryptographicSuite<M>>::TransformationParameters
    {
        TransformationOptions { type_: self.type_ }
    }

    fn hash_params(
        &self,
    ) -> <Ed25519Signature2020<M, P> as super::CryptographicSuite<M>>::HashParameters {
        Ed25519Signature2020::proof_configuration(self)
    }

    fn into_proof_params(
        self,
    ) -> <Ed25519Signature2020<M, P> as super::CryptographicSuite<M>>::ProofParameters {
        self
    }
}

impl<M: Clone + VerificationMethod, P: Clone + ProofPurpose>
    VerifyParams<M, Ed25519Signature2020<M, P>> for ProofOptions<Ed25519Signature2020<M, P>, M, P>
{
    fn transform_params(
        &self,
    ) -> <Ed25519Signature2020<M, P> as super::CryptographicSuite<M>>::TransformationParameters
    {
        TransformationOptions { type_: self.type_ }
    }

    fn into_hash_params(
        self,
    ) -> <Ed25519Signature2020<M, P> as super::CryptographicSuite<M>>::HashParameters {
        Ed25519Signature2020::proof_configuration(&self)
    }
}
