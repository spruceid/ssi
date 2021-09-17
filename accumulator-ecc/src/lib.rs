#[macro_use]
extern crate serde_big_array;

pub extern crate pairings;

big_array! { BigArray; 32,48,96,192 }

use crate::accumulator::Element;
use blake2::{digest::generic_array::GenericArray, Blake2b};
use ff_zeroize::Field;
use pairings::{
    bls12_381::{Fr, G1},
    hash_to_curve::HashToCurve,
    hash_to_field::{BaseFromRO, ExpandMsgXmd},
    CurveProjective,
};
#[cfg(not(test))]
use rand::prelude::*;
use std::ops::{AddAssign, MulAssign, SubAssign};

#[cfg(test)]
thread_local! {
    pub static MOCK_RNG: std::cell::RefCell<usize> = std::cell::RefCell::new(1);
}

/// Similar to https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
/// info is left blank
#[cfg(not(test))]
fn generate_fr(salt: &[u8], ikm: Option<&[u8]>) -> Fr {
    let info = [0u8, 32u8]; // I2OSP(L, 2)
    let ikm = match ikm {
        Some(v) => {
            let mut t = vec![0u8; v.len() + 1];
            t[..v.len()].copy_from_slice(v);
            t
        }
        None => {
            let mut bytes = vec![0u8; 33];
            thread_rng().fill_bytes(bytes.as_mut_slice());
            bytes[32] = 0;
            bytes
        }
    };
    let mut okm = [0u8; 48];
    let h = hkdf::Hkdf::<Blake2b>::new(Some(&salt[..]), &ikm);
    h.expand(&info[..], &mut okm).unwrap();
    Fr::from_okm(GenericArray::from_slice(&okm[..]))
}

#[cfg(test)]
fn generate_fr(salt: &[u8], seed: Option<&[u8]>) -> Fr {
    use ff_zeroize::PrimeField;

    match seed {
        Some(d) => {
            let info = [0u8, 32u8]; // I2OSP(L, 2)
            let mut okm = [0u8; 48];
            let h = hkdf::Hkdf::<Blake2b>::new(Some(&salt[..]), &d);
            h.expand(&info[..], &mut okm).unwrap();
            Fr::from_okm(GenericArray::from_slice(&okm[..]))
        }
        None => MOCK_RNG.with(|v| {
            let mut t = v.borrow_mut();
            *t = *t + 1;
            Fr::from_repr(pairings::bls12_381::FrRepr::from(*t as u64)).unwrap()
        }),
    }
}

fn hash_to_g1<I: AsRef<[u8]>>(data: I) -> G1 {
    const DST: &[u8] = b"BLS12381G1_XMD:BLAKE2B_SSWU_RO_VB_ACCUMULATOR:1_0_0";
    <G1 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(data.as_ref(), DST)
}

/// dA(x) and dD(x)
fn dad(values: &[Element], y: Fr) -> Fr {
    if values.len() == 1 {
        let mut a = values[0].0;
        a.sub_assign(&y);
        a
    } else {
        values
            .iter()
            .map(|v| {
                let mut vv = v.0;
                vv.sub_assign(&y);
                vv
            })
            .fold(Fr::one(), |mut a, y| {
                a.mul_assign(&y);
                a
            })
    }
}

/// Salt used for hashing values into the accumulator
/// Giuseppe Vitto, Alex Biryukov = VB
/// Accumulator = ACC
const SALT: &'static [u8] = b"VB-ACC-HASH-SALT-";

struct PolynomialG1(Vec<G1>);

impl PolynomialG1 {
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    pub fn evaluate(&self, x: Fr) -> Option<G1> {
        if self.0.is_empty() {
            return None;
        }

        let mut p = x;
        let mut res = self.0[0];

        for i in 1..self.0.len() {
            let mut r = self.0[i];
            r.mul_assign(p);
            res.add_assign(&r);
            p.mul_assign(&x);
        }
        Some(res)
    }
}

impl AddAssign for PolynomialG1 {
    fn add_assign(&mut self, rhs: Self) {
        let min_len = std::cmp::min(self.0.len(), rhs.0.len());

        if self.0.len() == min_len {
            for i in min_len..rhs.0.len() {
                self.0.push(rhs.0[i]);
            }
        }
        for i in 0..min_len {
            self.0[i].add_assign(&rhs.0[i])
        }
    }
}

impl MulAssign<Fr> for PolynomialG1 {
    fn mul_assign(&mut self, rhs: Fr) {
        for i in 0..self.0.len() {
            self.0[i].mul_assign(rhs);
        }
    }
}

struct Polynomial(Vec<Fr>);

impl Polynomial {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    pub fn push(&mut self, value: Fr) {
        self.0.push(value)
    }
}

impl Into<Vec<Fr>> for Polynomial {
    fn into(self) -> Vec<Fr> {
        self.0
    }
}

impl AddAssign for Polynomial {
    fn add_assign(&mut self, rhs: Self) {
        let min_len = std::cmp::min(self.0.len(), rhs.0.len());

        if self.0.len() == min_len {
            for i in min_len..rhs.0.len() {
                self.0.push(rhs.0[i]);
            }
        }
        for i in 0..min_len {
            self.0[i].add_assign(&rhs.0[i])
        }
    }
}

impl SubAssign for Polynomial {
    fn sub_assign(&mut self, rhs: Self) {
        let min_len = std::cmp::min(self.0.len(), rhs.0.len());
        if self.0.len() == min_len {
            for i in min_len..rhs.0.len() {
                let mut r = rhs.0[i];
                r.negate();
                self.0.push(r);
            }
        }
        for i in 0..min_len {
            self.0[i].sub_assign(&rhs.0[i]);
        }
    }
}

impl MulAssign for Polynomial {
    fn mul_assign(&mut self, rhs: Self) {
        let orig = self.0.clone();

        // Both vectors can't be empty
        if !self.0.is_empty() || !rhs.0.is_empty() {
            for i in 0..self.0.len() {
                self.0[i] = Fr::default();
            }
            // M + N - 1
            self.0
                .resize_with(self.0.len() + rhs.0.len() - 1, || Fr::default());

            // Calculate product
            for i in 0..orig.len() {
                for j in 0..rhs.0.len() {
                    let mut f = orig[i];
                    f.mul_assign(&rhs.0[j]);
                    self.0[i + j].add_assign(&f);
                }
            }
        }
    }
}

impl MulAssign<Fr> for Polynomial {
    fn mul_assign(&mut self, rhs: Fr) {
        for i in 0..self.0.len() {
            self.0[i].mul_assign(&rhs);
        }
    }
}

#[macro_use]
mod macros;

pub mod accumulator;
pub mod error;
pub mod key;
pub mod proof;
pub mod witness;

pub mod prelude {
    pub use super::accumulator::*;
    pub use super::error::*;
    pub use super::key::*;
    pub use super::proof::*;
    pub use super::witness::*;
}
