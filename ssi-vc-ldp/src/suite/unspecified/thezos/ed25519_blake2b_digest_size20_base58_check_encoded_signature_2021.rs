use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_vc::ProofValidity;
use ssi_verification_methods::{
    EcdsaSecp256k1RecoveryMethod2020, Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions, UntypedProof,
    UntypedProofRef,
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl_rdf_input_urdna2015!(EcdsaSecp256k1RecoveryMethod2020);

#[async_trait::async_trait]
impl CryptographicSuite for EcdsaSecp256k1RecoveryMethod2020 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<
        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    >;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod>,
        options: ProofOptions<Self::VerificationMethod>,
    ) -> Result<UntypedProof<Self::VerificationMethod>, SignatureError> {
        let Some(public_key) = options.context.public_key_jwk.as_deref() else {
			return Err(SignatureError::MissingPublicKey)
		};

        let jws = signer.sign(public_key.into(), &options.verification_method, data)?;
        Ok(UntypedProof::from_options(options, jws.into()))
    }

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: UntypedProofRef<'_, Self::VerificationMethod>,
    ) -> Result<ProofValidity, VerificationError> {
        let jws = proof
            .proof_value
            .as_jws()
            .ok_or(VerificationError::InvalidProof)?;

        let Some(public_key) = proof.context.public_key_jwk.as_deref() else {
			return Err(VerificationError::MissingPublicKey)
		};

        Ok(verifier
            .verify(
                public_key.into(),
                proof.verification_method,
                proof.proof_purpose,
                data,
                jws,
            )
            .await?
            .into())
    }
}
