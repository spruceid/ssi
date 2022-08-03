use crate::{b2fa, FACTOR_SIZE};
use common::{
    bigint::BigInteger,
    error::{AccumulatorError, AccumulatorErrorKind},
};
#[cfg(not(test))]
use rayon::prelude::*;
use std::convert::TryFrom;
use zeroize::Zeroize;

/// Represents the safe primes used in the modulus for the accumulator
#[derive(Debug, Eq, PartialEq)]
pub struct AccumulatorSecretKey {
    /// Must be a safe prime with MIN_SIZE_PRIME bits
    pub p: BigInteger,
    /// Must be a safe prime with MIN_SIZE_PRIME bits
    pub q: BigInteger,
}

impl AccumulatorSecretKey {
    /// Create a new Accumulator secret key by generating two
    /// 1024-bit safe primes
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute p * q
    pub fn modulus(&self) -> BigInteger {
        &self.p * &self.q
    }

    /// Compute (p - 1) * (q - 1)
    pub fn totient(&self) -> BigInteger {
        (&self.p - &BigInteger::from(1u32)) * (&self.q - &BigInteger::from(1u32))
    }

    /// Serialize to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut t = b2fa(&self.p, FACTOR_SIZE);
        t.append(b2fa(&self.q, FACTOR_SIZE).as_mut());
        t
    }
}

impl Default for AccumulatorSecretKey {
    fn default() -> Self {
        let (p, q) = gen_primes();
        Self { p, q }
    }
}

impl Clone for AccumulatorSecretKey {
    fn clone(&self) -> Self {
        Self {
            p: self.p.clone(),
            q: self.q.clone(),
        }
    }
}

impl TryFrom<&[u8]> for AccumulatorSecretKey {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 2 * FACTOR_SIZE {
            return Err(AccumulatorError::from_msg(
                AccumulatorErrorKind::InvalidType,
                format!(
                    "Invalid bytes, expected {}, got {}",
                    2 * FACTOR_SIZE,
                    data.len()
                ),
            ));
        }
        let p = BigInteger::try_from(&data[..FACTOR_SIZE])?;
        let q = BigInteger::try_from(&data[FACTOR_SIZE..])?;
        Ok(Self { p, q })
    }
}

impl TryFrom<Vec<u8>> for AccumulatorSecretKey {
    type Error = AccumulatorError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(data.as_slice())
    }
}

impl Zeroize for AccumulatorSecretKey {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
    }
}

impl Drop for AccumulatorSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

serdes_impl!(AccumulatorSecretKey);

#[cfg(not(test))]
fn gen_primes() -> (BigInteger, BigInteger) {
    use crate::MIN_SIZE_PRIME;
    let mut p: Vec<BigInteger> = (0..2)
        .collect::<Vec<usize>>()
        .par_iter()
        .map(|_| BigInteger::generate_safe_prime(MIN_SIZE_PRIME))
        .collect();
    let p1 = p.remove(0);
    let p2 = p.remove(0);
    (p1, p2)
}

#[cfg(test)]
fn gen_primes() -> (BigInteger, BigInteger) {
    // Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
    // because AccumulatorSecretKey::default() takes a long time
    let p = BigInteger::from("132590288326793330806752358172617836030510421524323425886695490513600853466362871997907908739315399849138190997738786757721539635477379820932279026029679011350046717599386392663749253953274352000157227488895139775977945940993648470523136879899410690348931562489237825925601577159953591977449106730133820825719");
    let q = BigInteger::from("149253707427499607752440533538420296779167710000842829107795675900185486091323606384260179778233711456748787559527972657213022998726578510459854530854900733457277643303592216900588246498239579922221956281290954735600574251392801029419096160964874150455156365996536205549377586240264971604869515447059744740119");
    (p, q)
}
