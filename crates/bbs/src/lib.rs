use ssi_claims_core::{InvalidProof, ProofValidationError, ProofValidity};
use ssi_verification_methods::{
    multikey::DecodedMultikey, MessageSignatureError, MultiSigningMethod, Multikey,
};
pub use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::{
    bbsplus::{ciphersuites::Bls12381Sha256, commitment::BlindFactor},
    schemes::algorithms::BBSplus,
};

#[derive(Debug)]
pub struct ProofGenFailed;

pub fn proof_gen(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<Vec<u8>, ProofGenFailed> {
    Ok(
        zkryptium::schemes::generics::PoKSignature::<BBSplus<Bls12381Sha256>>::proof_gen(
            pk,
            signature,
            Some(header),
            ph,
            Some(messages),
            Some(disclosed_indexes),
        )
        .map_err(|_| ProofGenFailed)?
        .to_bytes(),
    )
}

pub fn proof_verify(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    disclosed_messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<ProofValidity, ProofValidationError> {
    let signature =
        zkryptium::schemes::generics::PoKSignature::<BBSplus<Bls12381Sha256>>::from_bytes(
            signature,
        )
        .map_err(|_| ProofValidationError::InvalidSignature)?;

    Ok(signature
        .proof_verify(
            pk,
            Some(disclosed_messages),
            Some(disclosed_indexes),
            Some(header),
            ph,
        )
        .map_err(|_| InvalidProof::Signature))
}
pub enum Bbs {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        commitment_with_proof: Option<Vec<u8>>,
        signer_blind: Option<[u8; 32]>,
    },
}

impl MultiSigningMethod<BBSplusSecretKey, Bbs> for Multikey {
    fn sign_bytes_multi(
        &self,
        secret: &BBSplusSecretKey,
        algorithm: Bbs,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use zkryptium::schemes::generics::{BlindSignature, Signature};

        let DecodedMultikey::Bls12_381(pk) = self.public_key.decode()? else {
            return Err(MessageSignatureError::InvalidPublicKey);
        };

        let signature = match algorithm {
            Bbs::Baseline { header } => Signature::<BBSplus<Bls12381Sha256>>::sign(
                Some(messages),
                secret,
                pk,
                Some(&header),
            )
            .map_err(MessageSignatureError::signature_failed)?
            .to_bytes()
            .to_vec(),
            Bbs::Blind {
                header,
                commitment_with_proof,
                signer_blind,
            } => {
                let signer_blind = signer_blind.map(|b| BlindFactor::from_bytes(&b).unwrap());
                BlindSignature::<BBSplus<Bls12381Sha256>>::blind_sign(
                    secret,
                    pk,
                    commitment_with_proof.as_deref(),
                    Some(&header),
                    Some(messages),
                    signer_blind.as_ref(),
                )
                .map_err(MessageSignatureError::signature_failed)?
                .to_bytes()
                .to_vec()
            }
        };

        Ok(signature)
    }
}
