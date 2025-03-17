use multibase::Base;
use ssi_crypto::{AlgorithmInstance, Error, SignatureVerification, Signer};
use ssi_jwk::VerifyingKey;

use crate::{Proof, ProofRef};

pub async fn multibase_signing<S>(
    signer: impl Signer,
    signing_bytes: impl AsRef<[u8]>,
    mut proof: Proof<S>,
    algorithm: Option<AlgorithmInstance>,
    base: Base,
) -> Result<Proof<S>, Error> {
    let (_, algorithm) = signer.key_metadata().into_id_and_algorithm(algorithm)?;
    let signature = signer.sign(algorithm, signing_bytes.as_ref()).await?;
    proof.proof_value = Some(multibase::encode(base, signature));
    Ok(proof)
}

pub async fn multibase_verification<S>(
    verifier: impl VerifyingKey,
    signing_bytes: impl AsRef<[u8]>,
    proof: ProofRef<'_, S>,
    algorithm: Option<AlgorithmInstance>,
) -> Result<SignatureVerification, Error> {
    let encoded_signature = proof.proof_value.ok_or(Error::SignatureMissing)?;
    let (_, signature) =
        multibase::decode(encoded_signature).map_err(|_| Error::SignatureMalformed)?;
    let (_, algorithm) = verifier.key_metadata().into_id_and_algorithm(algorithm)?;
    verifier.verify_bytes(algorithm, signing_bytes.as_ref(), &signature)
}
