#![deny(
// warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
//! Implementation of a dynamic universal RSA accumulator
#[macro_use]
extern crate arrayref;
#[macro_use]
pub extern crate common;

pub(crate) const MIN_SIZE_PRIME: usize = 1024;
pub(crate) const FACTOR_SIZE: usize = MIN_SIZE_PRIME / 8;
pub(crate) const MIN_BYTES: usize = FACTOR_SIZE * 6 + 4;
pub(crate) const MEMBER_SIZE: usize = 32;
pub(crate) const MEMBER_SIZE_BITS: usize = 256;

/// Provides methods for creating and updating accumulators
pub mod accumulator;
/// Provides methods for hashing to prime
pub mod hash;
/// Provides an accumulator secret factors
pub mod key;
/// Proofs of set membership
pub mod proofmem;
/// Proofs of set non-membership
pub mod proofnon;
/// Provides non-membership witness methods
pub mod witnessnon;
/// Provides witness methods
pub mod witnessmem;

use crate::hash::hash_to_prime;
use blake2::{digest::Digest, Blake2b};
use common::{
    bigint::BigInteger,
    error::{AccumulatorError, AccumulatorErrorKind},
};
use std::convert::TryFrom;
use crate::hash::hash_to_generator;

/// Convenience module to include when using
pub mod prelude {
    pub use crate::{
        accumulator::Accumulator,
        common::{
            bigint::{BigInteger, GcdResult},
            error::*,
        },
        key::AccumulatorSecretKey,
        proofmem::MembershipProof,
        witnessmem::MembershipWitness,
        proofnon::NonMembershipProof,
        witnessnon::NonMembershipWitness,
    };
}

/// BigUint to fixed array
pub(crate) fn b2fa(b: &BigInteger, expected_size: usize) -> Vec<u8> {
    let mut t = vec![0u8; expected_size];
    let bt = b.to_bytes();
    assert!(
        expected_size >= bt.len(),
        "expected = {}, found = {}", expected_size, bt.len()
    );
    t[(expected_size - bt.len())..].clone_from_slice(bt.as_slice());
    t
}

pub(crate) fn hashed_generator<B: AsRef<[u8]>>(u: &BigInteger, a: &BigInteger, n: &BigInteger, nonce: B) -> BigInteger {
    let mut transcript = u.to_bytes();
    transcript.append(&mut a.to_bytes());
    transcript.extend_from_slice(nonce.as_ref());

    hash_to_generator(transcript.as_slice(), &n)
}

/// Represents a Proof of Knowledge of Exponents 2 from section 3.2 in
/// <https://eprint.iacr.org/2018/1188.pdf>
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Poke2Proof {
    u: BigInteger,
    z: BigInteger,
    q: BigInteger,
    r: BigInteger,
}

impl Poke2Proof {
    /// The size of this proof serialized
    pub const SIZE_BYTES: usize = 6 * FACTOR_SIZE + MEMBER_SIZE;

    /// Create a new proof of knowledge of exponents as described in
    /// Appendix D from
    /// <https://eprint.iacr.org/2018/1188.pdf>
    pub fn new<B: AsRef<[u8]>>(
        x: &BigInteger,
        u: &BigInteger,
        a: &BigInteger,
        n: &BigInteger,
        nonce: B,
    ) -> Self {
        let nonce = nonce.as_ref();
        let g = hashed_generator(u, a, n, nonce);
        Self::create(x, u, a, &g, n, nonce)
    }

    /// Same as `new` but allow any generator vs according to the spec
    pub fn create<B: AsRef<[u8]>>(
        x: &BigInteger,
        u: &BigInteger,
        a: &BigInteger,
        g: &BigInteger,
        n: &BigInteger,
        nonce: B,
    ) -> Self {
        let f = common::Field::new(n);
        let z = f.exp(&g, x);
        let (l, alpha) = Self::get_prime_and_alpha(&u, &a, &z, nonce.as_ref());

        // q = x / l
        // r = x % l
        let (whole, r) = BigInteger::div_rem(&x, &l);

        // Q = u ^ q * g ^ {q * alpha}
        let q = f.mul(&f.exp(&u, &whole), &f.exp(&g, &(&alpha * &whole)));
        Self {
            u: u.clone(),
            q,
            r,
            z,
        }
    }

    /// Verify a proof of knowledge of exponents
    pub fn verify<B: AsRef<[u8]>>(&self, value: &BigInteger, n: &BigInteger, nonce: B) -> bool {
        let nonce = nonce.as_ref();
        let g = hashed_generator(&self.u, &value, &n, nonce);
        self.check(&g, &value, &n, nonce)
    }

    /// Same as `verify` but allow custom `g`
    pub fn check<B: AsRef<[u8]>>(&self, g: &BigInteger, value: &BigInteger, n: &BigInteger, nonce: B) -> bool {
        let f = common::Field::new(n);
        let nonce = nonce.as_ref();
        let (l, alpha) = Self::get_prime_and_alpha(&self.u, &value, &self.z, nonce);

        // Q ^ l
        // let p1 = f.exp(&self.q, &l);
        // u ^ r
        // let p2 = f.exp(&self.u, &self.r);
        // alpha * r
        // g ^ {alpha * r}
        // let p3 = f.exp(&g, &(&alpha * &self.r));

        // Q^l * u^r * g^{x * r}
        // let left = f.mul(&p1, &f.mul(&p2, &p3));
        let left = f.mul(&f.mul(&f.exp(&self.q, &l), &f.exp(&self.u, &self.r)), &f.exp(g, &(&alpha * &self.r)));

        // v * z^x
        let right = f.mul(&value, &f.exp(&self.z, &alpha));

        left == right
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.u, 2 * FACTOR_SIZE);
        output.append(&mut b2fa(&self.z, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.q, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.r, MEMBER_SIZE));
        output
    }

    fn get_prime_and_alpha(u: &BigInteger, a: &BigInteger, z: &BigInteger, nonce: &[u8]) -> (BigInteger, BigInteger) {
        let mut data = u.to_bytes();
        data.append(&mut a.to_bytes());
        data.append(&mut z.to_bytes());
        data.extend_from_slice(nonce);

        // l = H2P( u || A || z || n1 )
        let l = hash_to_prime(data.as_slice());

        data.append(&mut l.to_bytes());
        // Fiat-Shamir
        // alpha = H(u || A || z || n1 || l)
        let alpha = BigInteger::try_from(Blake2b::digest(data.as_slice()).as_slice()).unwrap();
        (l, alpha)
    }
}

impl TryFrom<&[u8]> for Poke2Proof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != Self::SIZE_BYTES {
            return Err(AccumulatorErrorKind::SerializationError.into());
        }
        let u = BigInteger::try_from(&data[..(2 * FACTOR_SIZE)])?;
        let z = BigInteger::try_from(&data[(2 * FACTOR_SIZE)..(4 * FACTOR_SIZE)])?;
        let q = BigInteger::try_from(&data[(4 * FACTOR_SIZE)..(6 * FACTOR_SIZE)])?;
        let r = BigInteger::try_from(&data[(6 * FACTOR_SIZE)..])?;
        Ok(Self { u, z, q, r })
    }
}

serdes_impl!(Poke2Proof);
