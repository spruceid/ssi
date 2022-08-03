use crate::{accumulator::Accumulator, common::error::*, witnessmem::MembershipWitness, Poke2Proof};
use std::convert::TryFrom;

/// A proof of knowledge of exponents membership proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MembershipProof(Poke2Proof);

impl MembershipProof {
    /// Create a new PoKE2 proof
    pub fn new<B: AsRef<[u8]>>(
        witness: &MembershipWitness,
        accumulator: &Accumulator,
        nonce: B,
    ) -> Self {
        let proof = Poke2Proof::new(
            &witness.x,
            &witness.u,
            &accumulator.value,
            &accumulator.modulus,
            nonce,
        );
        Self(proof)
    }

    /// Verify a set membership proof
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        self.0.verify(&accumulator.value, &accumulator.modulus, nonce)
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl TryFrom<&[u8]> for MembershipProof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let proof = Poke2Proof::try_from(data)?;
        Ok(Self(proof))
    }
}

serdes_impl!(MembershipProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key::AccumulatorSecretKey, MEMBER_SIZE_BITS};
    use common::bigint::BigInteger;
    use rayon::prelude::*;

    #[test]
    fn proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            3u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = MembershipWitness::new(&acc, &members[0]).unwrap();
        let nonce = b"proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_assign(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
        assert_eq!(proof.to_bytes().len(), Poke2Proof::SIZE_BYTES);
    }

    #[test]
    fn big_proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<BigInteger> = (0..1_000)
            .collect::<Vec<_>>()
            .par_iter()
            .map(|_| BigInteger::generate_prime(MEMBER_SIZE_BITS))
            .collect();
        let mut acc = Accumulator::with_prime_members(&key, &members).unwrap();
        let witness = MembershipWitness::new_prime(&acc, &members[0]).unwrap();
        let nonce = b"big_proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_prime_assign(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
    }
}
