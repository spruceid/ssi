use blake2::{Blake2b, Digest};
use common::bigint::BigInteger;
use hkdf::Hkdf;
use std::convert::TryFrom;

/// Hashes `input` to a prime.
/// See Section 7 in
/// <https://eprint.iacr.org/2018/1188.pdf>
pub(crate) fn hash_to_prime<B: AsRef<[u8]>>(input: B) -> BigInteger {
    let mut input = input.as_ref().to_vec();
    let mut i = 1usize;
    let offset = input.len();
    input.extend_from_slice(&i.to_be_bytes()[..]);
    let end = input.len();

    let mut num;

    loop {
        let mut hash = Blake2b::digest(input.as_slice());
        // Force it to be odd
        hash[63] |= 1;
        // Only need 256 bits just borrow the bottom 32 bytes
        // There should be plenty of primes below 2^256
        // and we want this to be reasonably fast
        num = BigInteger::try_from(&hash[32..]).unwrap();
        if num.is_prime() {
            break;
        }
        i += 1;
        let i_bytes = i.to_be_bytes();
        input[offset..end].clone_from_slice(&i_bytes[..]);
    }
    num
}

/// Hashes `input` to a member of group `n`
/// that can be used as a generator `g`. `g` will be QR_N.
pub(crate) fn hash_to_generator<B: AsRef<[u8]>>(input: B, n: &BigInteger) -> BigInteger {
    let length = n.bits() / 8;
    let h = Hkdf::<Blake2b>::new(Some(b"RSA_ACCUMULATOR_HASH_TO_GENERATOR_"), input.as_ref());
    let mut okm = vec![0u8; length];
    h.expand(b"", &mut okm).unwrap();

    BigInteger::from(okm).mod_sqr(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gmp::mpz::{Mpz, ProbabPrimeResult};
    use rand::prelude::*;

    #[test]
    fn test_hash() {
        let t = hash_to_prime(b"This is a test to find a prime");
        let n = Mpz::from(t.to_bytes().as_slice());
        assert!(n.probab_prime(15) != ProbabPrimeResult::NotPrime);
        let mut bytes = vec![0u8; 32];
        for _ in 0..10 {
            thread_rng().fill_bytes(bytes.as_mut_slice());
            let t = hash_to_prime(&bytes);
            let n = Mpz::from(t.to_bytes().as_slice());
            assert!(n.probab_prime(15) != ProbabPrimeResult::NotPrime);
        }
    }
}
