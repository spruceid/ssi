use crate::{accumulator::Accumulator, b2fa, witnessnon::NonMembershipWitness, Poke2Proof, FACTOR_SIZE, MEMBER_SIZE};
use common::{bigint::BigInteger, error::*, Field};
use std::convert::TryFrom;

/// A proof of knowledge of exponents non-membership proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NonMembershipProof {
    v: BigInteger,
    r: BigInteger,
    q: BigInteger,
    z: BigInteger,
    proof_g: Poke2Proof,
}

impl NonMembershipProof {
    /// Create 2 new PoKE2 proofs
    pub fn new<B: AsRef<[u8]>>(
        witness: &NonMembershipWitness,
        accumulator: &Accumulator,
        nonce: B,
    ) -> Self {
        let nonce = nonce.as_ref();
        let f = Field::new(&accumulator.modulus);
        let v = f.exp(&accumulator.value, &witness.a);

        let gv_inv = f.mul(&f.inv(&accumulator.generator), &v);
        #[cfg(debug_assertions)]
        Self::check_witness(witness, accumulator);

        debug_assert_eq!(gv_inv, witness.b.mod_exp(&witness.x, &accumulator.modulus));

        let proof_v = Poke2Proof::new(&witness.a, &accumulator.value, &v, &accumulator.modulus, nonce);
        let proof_g = Poke2Proof::new(&witness.x, &witness.b, &gv_inv, &accumulator.modulus, nonce);
        Self {
            v,
            r: proof_v.r.clone(),
            q: proof_v.q.clone(),
            z: proof_v.z.clone(),
            proof_g,
        }
    }

    #[cfg(debug_assertions)]
    fn check_witness(witness: &NonMembershipWitness, accumulator: &Accumulator) {
        use rayon::prelude::*;

        let x_hat: BigInteger = accumulator.members.par_iter().product();
        let gcd_res = x_hat.bezouts_coefficients(&witness.x);
        let expected_b = accumulator.generator.mod_inverse(&accumulator.modulus).mod_exp(&gcd_res.b, &accumulator.modulus);
        assert_eq!(expected_b, witness.b);
    }

    /// Verify a set membership proof
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        let nonce = nonce.as_ref();
        let f = Field::new(&accumulator.modulus);
        let gv_inv = f.mul(&f.inv(&accumulator.generator), &self.v);
        // Copy the latest value of the accumulator so the proof will fail if
        // the accumulator value has changed since the proof was created
        let proof_v = Poke2Proof {
            u: accumulator.value.clone(),
            r: self.r.clone(),
            q: self.q.clone(),
            z: self.z.clone(),
        };
        let v_res = proof_v.verify(&self.v, &accumulator.modulus, nonce);
        let g_res = self.proof_g.verify( &gv_inv, &accumulator.modulus, nonce);
        g_res && v_res
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.v, 2 * FACTOR_SIZE);
        output.append(&mut b2fa(&self.z, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.q, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.r, MEMBER_SIZE));
        output.append(&mut self.proof_g.to_bytes());
        output
    }
}

impl TryFrom<&[u8]> for NonMembershipProof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != Poke2Proof::SIZE_BYTES * 2 + 2 * FACTOR_SIZE {
            return Err(AccumulatorErrorKind::SerializationError.into());
        }
        let mut offset = 2*FACTOR_SIZE;
        let v = BigInteger::try_from(&data[..offset])?;
        let mut end = offset + 2*FACTOR_SIZE;
        let z = BigInteger::try_from(&data[offset..end])?;

        offset = end;
        end = offset + 2*FACTOR_SIZE;

        let q = BigInteger::try_from(&data[offset..end])?;

        offset = end;
        end = offset + MEMBER_SIZE;

        let r = BigInteger::try_from(&data[offset..end])?;

        // let proof_v = Poke2Proof::try_from(&data[offset..end])?;
        let proof_g = Poke2Proof::try_from(&data[end..])?;
        Ok(Self {
            v,
            z,
            q,
            r,
            proof_g,
        })
    }
}

serdes_impl!(NonMembershipProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey as SecretKey;

    #[test]
    fn proof_test() {
        let key = SecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            3u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let member = 17u64.to_be_bytes();
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = NonMembershipWitness::new(&acc, &member).unwrap();
        let nonce = b"proof_test";

        let proof = NonMembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc += 17u64;

        assert!(!proof.verify(&acc, nonce));
        assert_eq!(
            proof.to_bytes().len(),
            2 * Poke2Proof::SIZE_BYTES
        );
    }
}
