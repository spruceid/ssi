pub use zkryptium::{
    bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey},
    errors::Error,
};
use zkryptium::{
    bbsplus::{
        ciphersuites::{BbsCiphersuite, Bls12381Sha256},
        commitment::BlindFactor,
    },
    keys::pair::KeyPair,
    schemes::{
        algorithms::BBSplus,
        generics::{BlindSignature, Signature},
    },
};

#[derive(Debug, Clone)]
pub enum SignatureParameters {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        commitment_with_proof: Option<Vec<u8>>,
        signer_blind: Option<[u8; 32]>,
    },
}

#[derive(Debug)]
pub struct ProofGenFailed;

pub struct InvalidSignature;

pub type ProofValidity = Result<(), InvalidSignature>;

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
) -> Result<ProofValidity, Error> {
    let signature =
        zkryptium::schemes::generics::PoKSignature::<BBSplus<Bls12381Sha256>>::from_bytes(
            signature,
        )?;

    Ok(signature
        .proof_verify(
            pk,
            Some(disclosed_messages),
            Some(disclosed_indexes),
            Some(header),
            ph,
        )
        .map_err(|_| InvalidSignature))
}

pub fn sign(
    params: SignatureParameters,
    sk: &BBSplusSecretKey,
    pk: &BBSplusPublicKey,
    messages: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    match params {
        SignatureParameters::Baseline { header } => {
            Ok(
                Signature::<BBSplus<Bls12381Sha256>>::sign(Some(messages), sk, pk, Some(&header))?
                    .to_bytes()
                    .into(),
            )
        }
        SignatureParameters::Blind {
            header,
            commitment_with_proof,
            signer_blind,
        } => {
            let signer_blind = signer_blind.map(|b| BlindFactor::from_bytes(&b).unwrap());
            Ok(BlindSignature::<BBSplus<Bls12381Sha256>>::blind_sign(
                sk,
                pk,
                commitment_with_proof.as_deref(),
                Some(&header),
                Some(messages),
                signer_blind.as_ref(),
            )?
            .to_bytes()
            .into())
        }
    }
}

pub fn generate_secret_key(rng: &mut impl rand::RngCore) -> BBSplusSecretKey {
    let mut key_material = [0; Bls12381Sha256::IKM_LEN];
    rng.fill_bytes(&mut key_material);
    let pair = KeyPair::<BBSplus<Bls12381Sha256>>::generate(&key_material, None, None).unwrap();
    pair.into_parts().0
}
