use crate::{accumulator::Element, generate_fr, BigArray, Polynomial};
use ff_zeroize::{Field, PrimeField};
use pairings::{
    bls12_381::{Fr, FrRepr, G2},
    serdes::SerDes,
    CurveProjective,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::Zeroize;

struct_impl!(
    /// Represents \alpha (secret key) on page 6 in
    /// <https://eprint.iacr.org/2020/777.pdf>
    #[derive(Clone, Debug, Zeroize)]
    #[zeroize(drop)]
    SecretKey,
    SecretKeyInner,
    Fr
);

impl SecretKey {
    pub const BYTES: usize = 32;

    /// Create a new secret key
    pub fn new(seed: Option<&[u8]>) -> Self {
        // Giuseppe Vitto, Alex Biryukov = VB
        // Accumulator = ACC
        Self(generate_fr(b"VB-ACC-KEYGEN-SALT-", seed))
    }

    /// Return the raw byte representation of the key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut o = [0u8; Self::BYTES];
        self.0.serialize(&mut o.as_mut(), true).unwrap();
        o
    }

    pub fn batch_additions(&self, additions: &[Element]) -> Element {
        Element(
            additions
                .iter()
                .map(|v| {
                    let mut vv = v.0;
                    vv.add_assign(&self.0);
                    vv
                })
                .fold(Fr::one(), |mut a, y| {
                    a.mul_assign(&y);
                    a
                }),
        )
    }

    pub fn batch_deletions(&self, deletions: &[Element]) -> Element {
        Element(self.batch_additions(deletions).0.inverse().unwrap())
    }

    /// Create the Batch Polynomial coefficients
    pub fn create_coefficients(
        &self,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Element> {
        // vD(x) = ∑^{m}_{s=1}{ ∏ 1..s {yD_i + alpha}^-1 ∏ 1 ..s-1 {yD_j - x}
        let one = Fr::from_repr(FrRepr::from(1u64)).unwrap();
        let mut m1 = one;
        m1.negate();
        let mut v_d = Polynomial::with_capacity(deletions.len());
        for s in 0..deletions.len() {
            // ∏ 1..s (yD_i + alpha)^-1
            let c = self.batch_deletions(&deletions[0..s + 1]).0;
            let mut poly = Polynomial::new();
            poly.push(one);
            // ∏ 1..(s-1) (yD_j - x)
            for j in 0..s {
                let mut t = Polynomial::new();
                t.push(deletions[j].0);
                t.push(m1);
                poly *= t;
            }
            poly *= c;
            v_d += poly;
        }

        //v_d(x) * ∏ 1..n (yA_i + alpha)
        v_d *= self.batch_additions(additions).0;

        // vA(x) = ∑^n_{s=1}{ ∏ 1..s-1 {yA_i + alpha} ∏ s+1..n {yA_j - x} }
        let mut v_a = Polynomial::with_capacity(additions.len());
        for s in 0..additions.len() {
            // ∏ 1..s-1 {yA_i + alpha}
            let c = if s == 0 {
                one
            } else {
                self.batch_additions(&additions[0..s]).0
            };
            let mut poly = Polynomial::new();
            poly.push(one);
            // ∏ s+1..n {yA_j - x}
            for j in (s + 1)..additions.len() {
                let mut t = Polynomial::new();
                t.push(additions[j].0);
                t.push(m1);
                poly *= t;
            }
            poly *= c;
            v_a += poly;
        }
        // vA - vD
        v_a -= v_d;

        v_a.0.iter().map(|b| Element(*b)).collect()
    }
}

struct_impl!(
    /// Represents \overline{Q} = \overline{P}*\alpha (public key) on page 6 in
    /// <https://eprint.iacr.org/2020/777.pdf>
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    PublicKey,
    PublicKeyInner,
    G2
);
display_impl!(PublicKey);

impl PublicKey {
    pub const BYTES: usize = 96;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        self.0.serialize(&mut d.as_mut(), true).unwrap();
        d
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let mut g2 = G2::one();
        g2.mul_assign(sk.0);
        Self(g2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairings::{bls12_381::G1, CurveProjective};

    #[test]
    fn batch_test() {
        let key = SecretKey::new(None);
        let data = vec![Element::hash(b"value1"), Element::hash(b"value2")];
        let add = key.batch_additions(data.as_slice());
        let del = key.batch_deletions(data.as_slice());
        let mut res = add.0;
        res.mul_assign(&del.0);
        assert_eq!(res, Fr::one());

        let mut g1 = G1::one();
        g1.mul_assign(add.0);
        g1.mul_assign(del.0);
        assert_eq!(g1, G1::one());

        g1.mul_assign(res);
        assert_eq!(g1, G1::one());
    }

    #[test]
    fn coefficient_test() {
        let key = SecretKey::new(Some(b"1234567890"));
        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let coefficients = key.create_coefficients(&data[0..2], &data[2..5]);
        assert_eq!(coefficients.len(), 3);
    }
}
