use std::marker::PhantomData;

use iref::IriBuf;
use ssi_rdf::IntoNQuads;

use crate::LinkedDataCredential;

use super::{
    Algorithm, DataIntegrityProof, InvalidProof, ProofConfiguration, ProofOptions, Signer,
    SignerProvider, TransformationOptions, Verifier, VerifierProvider,
};

/// Ed25519Signature2020 signature type.
pub struct Ed25519Signature2020<P = IriBuf>(PhantomData<P>);

impl<P> Clone for Ed25519Signature2020<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Ed25519Signature2020<P> {}

impl<P> Ed25519Signature2020<P> {
    pub fn proof_configuration<M>(
        options: &ProofOptions<Self, M, P>,
    ) -> ProofConfiguration<Self, M, P>
    where
        M: Clone,
        P: Clone,
    {
        ProofConfiguration {
            type_: options.type_,
            cryptosuite: options.cryptosuite.clone(),
            created: options.created,
            verification_method: options.verification_method.clone(),
            proof_purpose: options.proof_purpose.clone(),
        }
    }
}

impl<M, P> super::LinkedDataCryptographicSuite<M> for Ed25519Signature2020<P> {
    type TransformationParameters = TransformationOptions<Self>;
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self, M, P>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self, M, P>;
    type Proof = DataIntegrityProof<Self, M, P>;

    /// Transformation algorithm.
    fn transform<C: LinkedDataCredential>(
        &self,
        context: &mut C::Context,
        data: C,
        _options: TransformationOptions<Self>,
    ) -> Self::Transformed {
        data.canonical_form(context).into_iter().into_nquads()
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self, M, P>,
    ) -> Self::Hashed {
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
        data: Self::Hashed,
        signer_provider: impl SignerProvider<M>,
        options: ProofOptions<Self, M, P>,
    ) -> Self::Proof {
        let signer = signer_provider.get_signer(&options.verification_method);
        let sig = signer.sign(Algorithm::EdDSA, &data);
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);

        DataIntegrityProof::from_options(options, sig_multibase)
    }

    fn verify_proof(
        &self,
        verifier_provider: impl VerifierProvider<M>,
        data: Self::Hashed,
        proof: &Self::Proof,
    ) -> Result<(), InvalidProof> {
        let verifier = verifier_provider.get_verifier(&proof.verification_method);
        let proof_bytes = multibase::decode(&proof.proof_value)
            .map_err(|_| InvalidProof)?
            .1;
        if verifier.verify(Algorithm::EdDSA, &data, &proof_bytes) {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}
