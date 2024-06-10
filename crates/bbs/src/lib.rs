use ssi_verification_methods::{
    multikey::DecodedMultikey, MessageSignatureError, MultiSigningMethod, Multikey,
};
use zkryptium::bbsplus::commitment::BlindFactor;
pub use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};

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
        use zkryptium::{
            bbsplus::ciphersuites::Bls12381Sha256,
            schemes::{
                algorithms::BBSplus,
                generics::{BlindSignature, Signature},
            },
        };

        let DecodedMultikey::Bls12_381(pk) = self.decode()? else {
            return Err(MessageSignatureError::InvalidPublicKey);
        };

        let signature = match algorithm {
            Bbs::Baseline { header } => Signature::<BBSplus<Bls12381Sha256>>::sign(
                Some(messages),
                secret,
                &pk,
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
                    &pk,
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
