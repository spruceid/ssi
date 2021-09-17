use crate::{accumulator::Accumulator, b2fa, hash_to_prime, FACTOR_SIZE, MEMBER_SIZE};
use common::{bigint::BigInteger, Field, error::*};
use rayon::prelude::*;

/// A witness that can be used for non-membership proofs
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NonMembershipWitness {
    pub(crate) a: BigInteger,
    pub(crate) b: BigInteger,
    pub(crate) x: BigInteger,
}

impl NonMembershipWitness {
    /// Return a new non-membership witness
    pub fn new<B: AsRef<[u8]>>(accumulator: &Accumulator, x: B) -> Result<Self, AccumulatorError> {
        let x = hash_to_prime(x.as_ref());
        Self::new_prime(accumulator, &x)
    }

    /// Return a new non-membership witness with a value that is already prime
    pub fn new_prime(accumulator: &Accumulator, x: &BigInteger) -> Result<Self, AccumulatorError> {
        if accumulator.members.contains(&x) {
            return Err(AccumulatorError::from_msg(
                AccumulatorErrorKind::InvalidMemberSupplied,
                "value is in the accumulator",
            ));
        }
        let f = Field::new(&accumulator.modulus);
        let s: BigInteger = accumulator.members.par_iter().product();
        let gcd_res = s.bezouts_coefficients(x);
        let b = f.exp(&f.inv(&accumulator.generator), &gcd_res.b);
        debug_assert_eq!(f.exp(&b, &x), f.mul(&f.inv(&accumulator.generator), &f.exp(&accumulator.value, &gcd_res.a)));

        Ok(Self {
            a: gcd_res.a,
            b,
            x: x.clone(),
        })
    }

    /// Create a new witness to match `new_acc` from `old_acc` using this witness
    /// by applying the methods found in 4.2 in
    /// <https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf>
    pub fn update(&self, old_acc: &Accumulator, new_acc: &Accumulator) -> Result<Self, AccumulatorError> {
        let mut w = self.clone();
        w.update_assign(old_acc, new_acc)?;
        Ok(w)
    }

    /// Update this witness to match `new_acc` from `old_acc`
    /// by applying the methods found in 4.2 in
    /// <https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf>
    pub fn update_assign(&mut self, old_acc: &Accumulator, new_acc: &Accumulator) -> Result<(), AccumulatorError> {
        if new_acc.members.contains(&self.x) {
            return Err(AccumulatorErrorKind::InvalidMemberSupplied.into());
        }
        if old_acc.members.contains(&self.x) {
            return Err(AccumulatorErrorKind::InvalidMemberSupplied.into());
        }

        debug_assert_eq!(&old_acc.value.mod_exp(&self.a, &old_acc.modulus), &self.b.mod_exp(&self.x, &old_acc.modulus).mod_mul(&old_acc.generator, &old_acc.modulus));

        let additions: Vec<&BigInteger> = new_acc.members.difference(&old_acc.members).collect();
        let deletions: Vec<&BigInteger> = old_acc.members.difference(&new_acc.members).collect();

        if additions.is_empty() && deletions.is_empty() {
            return Ok(());
        }

        let f = Field::new(&new_acc.modulus);

        if !deletions.is_empty() {
            let x_hat = deletions.into_par_iter().product();
            let r = &(&x_hat * &self.a) / &self.x;
            self.a = (&self.a * &x_hat) - (&r * &self.x);
            self.b = f.mul(&self.b, &f.exp(&f.inv(&new_acc.value), &r));
            // Check if the assumption holds
            //\widehat{c}^\widehat{a} == g B^{x}
            debug_assert_eq!(f.exp(&new_acc.value, &self.a), f.mul(&new_acc.generator, &f.exp(&self.b, &self.x)));
        }

        // Section 4.2 in
        // <https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf>
        if !additions.is_empty() {
            let x_hat: BigInteger = additions.into_par_iter().product();
            let gcd_result = x_hat.bezouts_coefficients(&self.x);

            debug_assert_eq!(BigInteger::from(1), &x_hat * &gcd_result.a + &self.x * &gcd_result.b);

            let a_hat = self.a.mod_mul(&gcd_result.a, &self.x);

            debug_assert_eq!(&self.a % &self.x, a_hat.mod_mul(&x_hat, &self.x));

            let r = &(&(&a_hat * &x_hat) - &self.a) / &self.x;

            debug_assert_eq!(&BigInteger::from(0), &(&(&self.a + &(&r * &self.x)) % &x_hat));

            let field = Field::new(&self.a);

            debug_assert_eq!(field.mul(&a_hat, &x_hat), field.mul(&r, &self.x));

            let b_hat = f.mul(&self.b, &f.exp(&old_acc.value, &r));

            self.a = a_hat;
            self.b = b_hat;
            // c_hat^a_hat == b_hat^x g
            debug_assert_eq!(f.exp(&new_acc.value, &self.a), f.mul(&new_acc.generator, &f.exp(&self.b, &self.x)));
        }

        Ok(())
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.a, FACTOR_SIZE * 2);
        output.append(&mut b2fa(&self.b, FACTOR_SIZE * 2));
        output.append(&mut b2fa(&self.x, MEMBER_SIZE));
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey as SecretKey;
    use crate::MEMBER_SIZE_BITS;

    #[ignore]
    #[test]
    fn witnesses() {
        let key = SecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            23u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let member = 17u64.to_be_bytes();
        let acc = Accumulator::with_members(&key, &members);
        let witness = NonMembershipWitness::new(&acc, &member).unwrap();
        let x = hash_to_prime(&member);
        assert_eq!(witness.x, x);
        assert_eq!(
            witness.a,
            BigInteger::from(
                "-15810496871052012929721951174424824308288730437435807996081044306834293553183"
            )
        );
        assert_eq!(witness.b, BigInteger::from("19731949503840799383004983499976351402593806159011822165741044085004905054673855363251385357597006492205730905650466488066773470871149400842396325545777674920024532296129116696323189577451048138544518857167383327747625073230517859862062456981747960458354502115002928340061239460009397008827664942646578083788378616855856348273253698783745015718408649373541254454588228353839211861287000689818331397142653546216894453995644059116432377166068316662466227209474894641100413409398337545057792037057027550522667399457451683638422319281726301941188118255274194652039389040737481315040156989596592391081668567908550005221922"));

        assert_eq!(witness.to_bytes().len(), 4 * FACTOR_SIZE + MEMBER_SIZE);
    }

    #[test]
    fn updates() {
        let key = SecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            23u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
            17u64.to_be_bytes(),
            19u64.to_be_bytes(),
        ];
        let member = 37u64.to_be_bytes();
        let acc = Accumulator::with_members(&key, &members);
        let witness = NonMembershipWitness::new(&acc, &member).unwrap();

        // Test add update
        let acc_prime = &acc + 29u64;

        let res = witness.update(&acc, &acc_prime);
        assert!(res.is_ok());
        let new_w = res.unwrap();

        let expected_witness = NonMembershipWitness::new(&acc_prime, &member).unwrap();
        assert_eq!(expected_witness.a, new_w.a);
        assert_eq!(expected_witness.b, new_w.b);

        // Test remove update
        let mut new_acc = acc_prime.remove_u64(&key, 19u64).unwrap();
        let res = new_w.update(&acc_prime, &new_acc);
        assert!(res.is_ok());
        let new_w = res.unwrap();
        let expected_witness = NonMembershipWitness::new(&new_acc, &member).unwrap();
        assert_eq!(expected_witness.a, new_w.a);
        assert_eq!(expected_witness.b, new_w.b);

        let acc_prime = new_acc.clone();
        new_acc += 31u64;
        new_acc += 41u64;
        new_acc += 47u64;
        let res = new_w.update(&acc_prime, &new_acc);
        assert!(res.is_ok());
        let new_w = res.unwrap();
        let expected_witness = NonMembershipWitness::new(&new_acc, &member).unwrap();
        assert_eq!(expected_witness.a, new_w.a);
        assert_eq!(expected_witness.b, new_w.b);
    }

    #[test]
    fn big_updates() {
        let key = SecretKey::default();
        let members = (0..10).collect::<Vec<_>>().par_iter().map(|_| BigInteger::generate_prime(MEMBER_SIZE_BITS)).collect::<Vec<BigInteger>>();
        let x = BigInteger::generate_prime(MEMBER_SIZE_BITS);

        let acc = Accumulator::with_prime_members(&key, &members).unwrap();
        let witness = NonMembershipWitness::new_prime(&acc, &x).unwrap();

        // let mut new_acc = acc.clone();
        let mut new_members = Vec::new();
        for _ in 0..3 {
            // acc.insert_prime(&BigInteger::generate_prime(MEMBER_SIZE_BITS)).unwrap();
            new_members.push(BigInteger::generate_prime(MEMBER_SIZE_BITS));
        }

        let new_acc = acc.add_prime_members(new_members.as_slice());
        assert!(new_acc.is_ok());
        let new_acc = new_acc.unwrap();
        let res = witness.update(&acc, &new_acc);
        assert!(res.is_ok());
        let new_w = res.unwrap();

        let expected_w = NonMembershipWitness::new_prime(&new_acc, &x).unwrap();
        assert_eq!(expected_w.a, new_w.a);
        assert_eq!(expected_w.b, new_w.b);
    }
}
