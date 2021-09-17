use crate::{generate_fr, key::SecretKey, BigArray, SALT};
use ff_zeroize::Field;
use pairings::{
    bls12_381::{Fr, G1},
    serdes::SerDes,
    CurveProjective,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

struct_impl!(
    /// An element in the accumulator
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    Element,
    ElementInner,
    Fr
);
display_impl!(Element);

impl Element {
    pub const BYTES: usize = 32;

    pub fn one() -> Self {
        Self(Fr::one())
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        self.0.serialize(&mut d.as_mut(), true).unwrap();
        d
    }

    pub fn hash(d: &[u8]) -> Self {
        Self(generate_fr(SALT, Some(d)))
    }

    pub fn random() -> Self {
        Self(generate_fr(SALT, None))
    }
}

struct_impl!(
    /// A coefficent for updating witnesses
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    Coefficient,
    CoefficientInner,
    G1
);

impl Coefficient {
    pub const BYTES: usize = 48;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        self.0.serialize(&mut d.as_mut(), true).unwrap();
        d
    }
}

display_impl!(Coefficient);

struct_impl!(
    /// Represents a Universal Bilinear Accumulator.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    Accumulator,
    AccumulatorInner,
    G1
);

impl Accumulator {
    pub const BYTES: usize = 48;

    /// Create a new accumulator that supports a maximum number of non-membership witnesses
    /// setting `non_member_witness_max` to 0 makes this just a dynamic accumulator
    /// because care must be taken with non-membership witnesses to avoid the attack
    /// from <https://eprint.iacr.org/2020/598>.
    /// Another option is to add multiple values if non-membership is to be supported
    /// where one is known to the witness holder and the other is retained.
    /// See also section 7 in <https://eprint.iacr.org/2020/777>
    pub fn new(key: &SecretKey, non_member_witness_max: usize) -> Self {
        // TODO: Implement Accumulator Initialization as described in section 7 of
        // <https://eprint.iacr.org/2020/777.pdf>
        // for now just do random elements as described in 8.1 on
        // <https://eprint.iacr.org/2020/598.pdf>
        // however, this has the drawback that, unless these values are stored somewhere
        // and kept secret, there could be collisions with real values later but the odds
        // of this are very small.
        let mut p = G1::one();
        if non_member_witness_max > 0 {
            let y = (0..=non_member_witness_max)
                .collect::<Vec<_>>()
                .par_iter()
                .map(|_| {
                    let mut y = generate_fr(SALT, None);
                    y.add_assign(&key.0);
                    y
                })
                .reduce(Fr::one, |mut a, y| {
                    a.mul_assign(&y);
                    a
                });
            p.mul_assign(y);
        }
        Self(p)
    }

    /// Initialize a new accumulator prefilled with entries
    /// Each member is assumed to be hashed
    pub fn with_elements(key: &SecretKey, non_member_witness_max: usize, m: &[Element]) -> Self {
        let mut acc = Self::new(key, non_member_witness_max);
        let y = key.batch_additions(m.as_ref());
        acc.0.mul_assign(y.0);
        acc
    }

    /// Add many members
    pub fn add_elements(&self, key: &SecretKey, m: &[Element]) -> Self {
        let mut acc = self.clone();
        acc.add_elements_assign(key, m);
        acc
    }

    /// Add many members
    pub fn add_elements_assign(&mut self, key: &SecretKey, m: &[Element]) {
        let y = key.batch_additions(m.as_ref());
        self.0.mul_assign(y.0);
    }

    /// Add a value to the accumulator, the value will be hashed to a prime number first
    pub fn add(&self, key: &SecretKey, value: &Element) -> Self {
        let mut a = self.clone();
        a.add_assign(key, value);
        a
    }

    /// Add a value an update this accumulator
    pub fn add_assign(&mut self, key: &SecretKey, value: &Element) {
        let mut v = key.0;
        v.add_assign(&value.0);
        self.0.mul_assign(v);
    }

    /// Remove a value from the accumulator and return
    /// a new accumulator without `value`
    pub fn remove(&self, key: &SecretKey, value: &Element) -> Self {
        let mut a = self.clone();
        a.remove_assign(key, value);
        a
    }

    /// Remove a value from the accumulator if it exists
    pub fn remove_assign(&mut self, key: &SecretKey, value: &Element) {
        let mut v = key.0;
        v.add_assign(&value.0);
        v = v.inverse().unwrap();
        self.0.mul_assign(v);
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update(
        &self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> (Self, Vec<Coefficient>) {
        let mut a = self.clone();
        let c = a.update_assign(key, additions, deletions);
        (a, c)
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update_assign(
        &mut self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Coefficient> {
        let mut a = key.batch_additions(additions);
        let d = key.batch_deletions(deletions);

        a.0.mul_assign(&d.0);
        let coefficients = key
            .create_coefficients(additions, deletions)
            .iter()
            .map(|c| {
                let mut v = self.0;
                v.mul_assign(c.0);
                Coefficient(v)
            })
            .collect();
        self.0.mul_assign(a.0);
        coefficients
    }

    /// Convert accumulator to bytes
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut v = [0u8; 48];
        self.0.serialize(&mut v.as_mut(), true).unwrap();
        v
    }
}

display_impl!(Accumulator);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PublicKey;
    use crate::proof::ProofParams;

    #[test]
    fn new_accmulator_100() {
        let key = SecretKey::new(None);
        let acc = Accumulator::new(&key, 100);
        assert_ne!(acc.0, G1::zero());
    }

    #[allow(non_snake_case)]
    #[test]
    fn new_accumulator_10K() {
        let key = SecretKey::new(None);
        let acc = Accumulator::new(&key, 10_000);
        assert_ne!(acc.0, G1::zero());
    }

    #[allow(non_snake_case)]
    #[test]
    fn new_accumulator_10M() {
        let key = SecretKey::new(None);
        let acc = Accumulator::new(&key, 10_000_000);
        assert_ne!(acc.0, G1::zero());
    }

    #[test]
    fn one_year_updates() {
        use crate::proof::MembershipProofCommitting;
        use crate::witness::MembershipWitness;
        use std::time::SystemTime;

        const DAYS: usize = 3;

        let key = SecretKey::new(None);
        let pk = PublicKey::from(&key);
        let mut items: Vec<Element> = (0..10_000_000).map(|_| Element::random()).collect();
        let mut acc = Accumulator::with_elements(&key, 0, items.as_slice());

        let mut witness = MembershipWitness::new(items.last().unwrap(), acc, &key);
        let params = ProofParams::new(pk, None);
        let committing = MembershipProofCommitting::new(&witness, acc, params, pk, None);
        let challenge = Element::hash(committing.get_bytes_for_challenge().as_slice());
        let proof = committing.gen_proof(challenge);
        let finalized = proof.finalize(acc, params, pk, challenge);
        assert_eq!(
            Element::hash(finalized.get_bytes_for_challenge().as_slice()),
            challenge
        );

        let mut deltas = Vec::with_capacity(DAYS);
        for i in 0..DAYS {
            let additions: Vec<Element> = (0..1000).map(|_| Element::random()).collect();
            let (deletions, titems) = items.split_at(600);
            let t = titems.to_vec();
            let deletions = deletions.to_vec();
            items = t;
            println!("Update for single day: {}", i + 1);
            let before = SystemTime::now();
            let coefficients = acc.update_assign(&key, additions.as_slice(), deletions.as_slice());
            let time = SystemTime::now().duration_since(before).unwrap();
            println!("Time to complete: {:?}", time);
            deltas.push((additions, deletions, coefficients));
        }

        println!("Update witness");
        let before = SystemTime::now();
        witness.multi_batch_update_assign(deltas.as_slice());
        let time = SystemTime::now().duration_since(before).unwrap();
        println!("Time to complete: {:?}", time);
        let committing = MembershipProofCommitting::new(&witness, acc, params, pk, None);
        let challenge = Element::hash(committing.get_bytes_for_challenge().as_slice());
        let proof = committing.gen_proof(challenge);
        let finalized = proof.finalize(acc, params, pk, challenge);
        assert_eq!(
            Element::hash(finalized.get_bytes_for_challenge().as_slice()),
            challenge
        );
    }

    #[test]
    fn add_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator::new(&key, 0);
        acc.add_assign(&key, &Element::hash(b"value1"));
        assert_ne!(acc.0, G1::one());
    }

    #[test]
    fn sub_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator::new(&key, 0);
        assert_eq!(acc.0, G1::one());
        acc.add_assign(&key, &Element::hash(b"value1"));
        assert_ne!(acc.0, G1::one());
        acc.remove_assign(&key, &Element::hash(b"value1"));
        assert_eq!(acc.0, G1::one());
    }

    #[test]
    fn batch_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator::new(&key, 0);
        let values = &[Element::hash(b"value1"), Element::hash(b"value2")];
        acc.update_assign(&key, values, &[]);
        assert_ne!(acc.0, G1::one());
        acc.update_assign(&key, &[], values);
        assert_eq!(acc.0, G1::one());
    }
}
