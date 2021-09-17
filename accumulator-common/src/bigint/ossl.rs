use super::GcdResult;
use crate::error::AccumulatorError;
use openssl::bn::*;
use std::{
    ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Div, DivAssign, Rem, RemAssign},
    cmp::Ordering,
    convert::TryFrom,
    str::FromStr
};
use zeroize::Zeroize;

#[inline]
fn clone_bignum(b: &BigNum) -> BigNum {
    BigNum::from_slice(b.to_vec().as_slice()).unwrap()
}

/// A Big Integer Implementation backed by OpenSSL BigNum
#[derive(Debug)]
pub struct OsslBigInt {
    pub(crate) value: BigNum,
}

impl std::fmt::Display for OsslBigInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OsslBigInt {{ value: {} }}", self.value.to_dec_str().unwrap())
    }
}

impl Clone for OsslBigInt {
    fn clone(&self) -> Self {
        Self {
            value: clone_bignum(&self.value),
        }
    }
}

impl PartialEq for OsslBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for OsslBigInt {}

impl PartialOrd for OsslBigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl Ord for OsslBigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl Default for OsslBigInt {
    fn default() -> Self {
        Self { value: BigNum::new().unwrap() }
    }
}

impl OsslBigInt {
    /// Used by the std::ops::Add methods
    fn add_(&self, rhs: &Self) -> Self {
        let mut value = BigNum::new().unwrap();
        BigNumRef::checked_add(&mut value, &self.value, &rhs.value).unwrap();
        Self { value }
    }

    /// Used by the std::ops::AddAssign methods
    fn add_assign_(&mut self, rhs: &Self) {
        let value = clone_bignum(&self.value);
        BigNumRef::checked_add(&mut self.value, &value, &rhs.value).unwrap();
    }

    /// Used by the std::ops::Sub methods
    fn sub_(&self, rhs: &Self) -> Self {
        let mut value = BigNum::new().unwrap();
        BigNumRef::checked_sub(&mut value, &self.value, &rhs.value).unwrap();
        Self { value }
    }

    /// Used by the std::ops::SubAssign methods
    fn sub_assign_(&mut self, rhs: &Self) {
        let value = clone_bignum(&self.value);
        BigNumRef::checked_sub(&mut self.value, &value, &rhs.value).unwrap();
    }

    /// Used by the std::ops::Mul methods
    fn mul_(&self, rhs: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut value = BigNum::new().unwrap();
        BigNumRef::checked_mul(&mut value, &self.value, &rhs.value, &mut ctx).unwrap();
        Self { value }
    }

    /// Used by the std::ops::MulAssign methods
    fn mul_assign_(&mut self, rhs: &Self) {
        let mut ctx = BigNumContext::new().unwrap();
        let value = clone_bignum(&self.value);
        BigNumRef::checked_mul(&mut self.value, &value, &rhs.value, &mut ctx).unwrap();
    }

    /// Used by the std::ops::Div methods
    fn div_(&self, rhs: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut value = BigNum::new().unwrap();
        BigNumRef::checked_div(&mut value, &self.value, &rhs.value, &mut ctx).unwrap();
        Self { value }
    }

    /// Used by the std::ops::DivAssign methods
    fn div_assign_(&mut self, rhs: &Self) {
        let mut ctx = BigNumContext::new().unwrap();
        let value = clone_bignum(&self.value);
        BigNumRef::checked_div(&mut self.value, &value, &rhs.value, &mut ctx).unwrap();
    }

    /// Used by the std::ops::Rem methods
    fn rem_(&self, rhs: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut value = BigNum::new().unwrap();
        BigNumRef::nnmod(&mut value, &self.value, &rhs.value, &mut ctx).unwrap();
        Self { value }
    }

    /// Used by the std::ops::RemAssign methods
    fn rem_assign_(&mut self, rhs: &Self) {
        let mut ctx = BigNumContext::new().unwrap();
        let value = clone_bignum(&self.value);
        BigNumRef::nnmod(&mut self.value, &value, &rhs.value, &mut ctx).unwrap();
    }

    /// Compute the quotient and remainder and return both
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let mut ctx = BigNumContext::new().unwrap();
        let mut q = BigNum::new().unwrap();
        let mut r = BigNum::new().unwrap();
        BigNumRef::div_rem(&mut q, &mut r, &self.value, &rhs.value, &mut ctx).unwrap();
        (Self { value: q }, Self { value: r })
    }

    /// Compute modular exponentiation and return the result
    /// result = self ^ rhs mod order
    pub fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let one = BigNum::from_u32(1u32).unwrap();
        if exponent.value == BigNum::new().unwrap() {
            return Self { value: one };
        }
        if exponent.value == one {
            return self.clone();
        }
        let mut value = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        if exponent.value.is_negative() {
            let mut exp = clone_bignum(&exponent.value);
            let mut temp = BigNum::new().unwrap();
            BigNumRef::mod_inverse(&mut temp, &self.value, &modulus.value, &mut ctx).unwrap();
            exp.set_negative(false);
            BigNumRef::mod_exp(&mut value, &temp, &exp, &modulus.value, &mut ctx).unwrap();
        } else {
            BigNumRef::mod_exp(&mut value, &self.value, &exponent.value,  &modulus.value, &mut ctx).unwrap();
        }
        Self { value }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ exponent mod order
    pub fn mod_exp_assign(&mut self, exponent: &Self, modulus: &Self) {
        let one = BigNum::from_u32(1u32).unwrap();
        if exponent.value == BigNum::new().unwrap() {
            self.value = one;
            return;
        }
        if exponent.value == one {
            return;
        }
        let value = clone_bignum(&self.value);
        let mut ctx = BigNumContext::new().unwrap();
        if exponent.value.is_negative() {
            let mut exp = clone_bignum(&exponent.value);
            let mut temp = BigNum::new().unwrap();
            BigNumRef::mod_inverse(&mut temp, &value, &modulus.value, &mut ctx).unwrap();
            exp.set_negative(false);
            BigNumRef::mod_exp(&mut self.value, &temp, &exp, &modulus.value, &mut ctx).unwrap();
        } else {
            BigNumRef::mod_exp(&mut self.value, &value, &exponent.value,&modulus.value, &mut ctx).unwrap();
        }
    }

    /// Compute modular square and return the result
    /// result = self ^ 2 mod order
    pub fn mod_sqr(&self, modulus: &Self) -> Self {
        let mut value = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_sqr(&mut value, &self.value, &modulus.value, &mut ctx).unwrap();
        Self { value }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ 2 mod order
    pub fn mod_sqr_assign(&mut self, modulus: &Self) {
        let value = clone_bignum(&self.value);
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_sqr(&mut self.value, &value, &modulus.value, &mut ctx).unwrap();
    }

    /// Compute modular inverse and return the result
    /// result = self ^ -1 mod order
    pub fn mod_inverse(&self, modulus: &Self) -> Self {
        let mut value = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_inverse(&mut value, &self.value, &modulus.value, &mut ctx).unwrap();
        Self { value }
    }

    /// Compute modular inverse and assign it to self
    /// self = self ^ -1 mod order
    pub fn mod_inverse_assign(&mut self, modulus: &Self) {
        let value = clone_bignum(&self.value);
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_inverse(&mut self.value, &value, &modulus.value, &mut ctx).unwrap();
    }

    /// Compute modular multiplication and return the result
    /// result = self * rhs mod order
    pub fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        let mut value = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_mul(&mut value, &self.value, &rhs.value, &modulus.value, &mut ctx).unwrap();
        Self {
            value
        }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self * rhs mod order
    pub fn mod_mul_assign(&mut self, rhs: &Self, modulus: &Self) {
        let value = clone_bignum(&self.value);
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_mul(&mut self.value, &value, &rhs.value,&modulus.value, &mut ctx).unwrap();
    }

    /// Generate a prime number of `size` bits
    pub fn generate_prime(size: usize) -> Self {
        let mut value = BigNum::new().unwrap();
        BigNumRef::generate_prime(&mut value, size as i32, false, None, None).unwrap();
        Self { value }
    }

    /// Generate a safe prime number of `size` bits
    pub fn generate_safe_prime(size: usize) -> Self {
        let mut value = BigNum::new().unwrap();
        BigNumRef::generate_prime(&mut value, size as i32, true, None, None).unwrap();
        Self { value }
    }

    /// Generate a random value less than `self`
    pub fn rand_range(&self) -> Self {
        let mut value = BigNum::new().unwrap();
        self.value.rand_range(&mut value).unwrap();
        Self { value }
    }

    /// Determine if `self` is a prime number
    pub fn is_prime(&self) -> bool {
        let mut ctx = BigNumContext::new().unwrap();
        self.value.is_prime(15, &mut ctx).unwrap()
    }

    /// Computes Bézout's coefficients and returns `s` and `t`
    /// using the extended euclidean algorithm
    /// Eventually replace with lehmer's GCD, see
    /// Based on https://github.com/golang/go/blob/master/src/math/big/int.go#L612
    /// and https://github.com/dignifiedquire/num-bigint/blob/master/src/algorithms/gcd.rs#L239
    pub fn bezouts_coefficients(&self, rhs: &Self) -> GcdResult {
        let zero = BigNum::new().unwrap();

        if self.value == zero && rhs.value == zero {
            return GcdResult {
                value: Self::default(),
                a: Self::default(),
                b: Self::default()
            };
        }
        if self.value == zero {
            return GcdResult {
                value: Self::default(),
                a: Self::default(),
                b: Self::from(1u32)
            };
        }
        if rhs.value == zero {
            return GcdResult {
                value: Self::default(),
                a: Self::from(1u32),
                b: Self::default()
            };
        }

        let mut s = BigNum::new().unwrap();
        let mut old_s = BigNum::from_u32(1).unwrap();
        let mut t = BigNum::from_u32(1).unwrap();
        let mut old_t = BigNum::new().unwrap();
        let mut r = clone_bignum(&rhs.value);
        let mut old_r = clone_bignum(&self.value);
        let mut ctx = BigNumContext::new().unwrap();

        let mut t_r = BigNum::new().unwrap();
        let mut t_s = BigNum::new().unwrap();
        let mut t_t = BigNum::new().unwrap();
        let mut n_r = BigNum::new().unwrap();
        let mut n_s = BigNum::new().unwrap();
        let mut n_t = BigNum::new().unwrap();

        while r != zero {
            let mut q = BigNum::new().unwrap();
            BigNumRef::checked_div(&mut q, &old_r, &r, &mut ctx).unwrap();

            BigNumRef::checked_mul(&mut t_r, &q, &r, &mut ctx).unwrap();
            BigNumRef::checked_mul(&mut t_s, &q, &s, &mut ctx).unwrap();
            BigNumRef::checked_mul(&mut t_t, &q, &t, &mut ctx).unwrap();

            BigNumRef::checked_sub(&mut n_r, &old_r, &t_r).unwrap();
            BigNumRef::checked_sub(&mut n_s, &old_s, &t_s).unwrap();
            BigNumRef::checked_sub(&mut n_t, &old_t, &t_t).unwrap();

            core::mem::swap(&mut old_r, &mut r);
            core::mem::swap(&mut old_s, &mut s);
            core::mem::swap(&mut old_t, &mut t);

            core::mem::swap(&mut r, &mut n_r);
            core::mem::swap(&mut s, &mut n_s);
            core::mem::swap(&mut t, &mut n_t);
        }

        GcdResult {
            value: Self { value: old_r },
            a: Self { value: old_s },
            b: Self { value: old_t }
        }
    }

    /// The number of bits needed to represent `self`
    pub fn bits(&self) -> usize {
        self.value.num_bits() as usize
    }

    // pub fn lehmer_gcd(&self, rhs: &Self) -> (Self, Self) {
    //     let zero = BigNum::new().unwrap();
    //
    //     if self.value == zero && rhs.value == zero {
    //         return (OsslBigInt { value: zero }, OsslBigInt { value: BigNum::new().unwrap() })
    //     }
    //     if self.value == zero {
    //         return (OsslBigInt{ value: zero }, OsslBigInt { value: BigNum::from_u32(1).unwrap() })
    //     }
    //     if rhs.value == zero {
    //         return (OsslBigInt{ value: BigNum::from_u32(1).unwrap() }, OsslBigInt { value: zero })
    //     }
    //
    //     let mut a;
    //     let mut b;
    //
    //     // `ua` tracks how many times input `self` has been accumulated into `a`
    //     let mut ua;
    //     // `ub` tracks how many times input `self` has been accumulated into `b`
    //     let mut ub;
    //
    //     let mut ctx = BigNumContext::new().unwrap();
    //
    //     if self.value < rhs.value {
    //         a = clone_bignum(&rhs.value);
    //         b = clone_bignum(&self.value);
    //         ua = BigNum::new().unwrap();
    //         ub = BigNum::from_u32(1).unwrap();
    //     } else {
    //         a = clone_bignum(&self.value);
    //         b = clone_bignum(&rhs.value);
    //         ua = BigNum::from_u32(1).unwrap();
    //         ub = BigNum::new().unwrap();
    //     }
    //     a.set_negative(false);
    //     b.set_negative(false);
    //
    //     let mut q = BigNum::new().unwrap();
    //     let mut r = BigNum::new().unwrap();
    //     let mut s = BigNum::new().unwrap();
    //     let mut t = BigNum::new().unwrap();
    //
    //     let mut b_len = b.num_bytes();
    //     while b_len > 1 {
    //         // Attempt to calculate in single-precision using leading words of `a` and `b`
    //         let (u0, u1, v0, v1, even) = lehmer_simulate(&a, &b);
    //
    //         if v0 != 0 {
    //             // Simulate the effect of the single-precision steps using cosequences
    //             // a = u0 * a + v0 * b
    //             // b = u1 * a + v1 * b
    //             lehmer_update(
    //                 &mut a,
    //                 &mut b,
    //                 &mut q,
    //                 &mut r,
    //                 &mut s,
    //                 &mut t,
    //                 u0,
    //                 u1,
    //                 v0,
    //                 v1,
    //                 even,
    //                 &mut ctx
    //             );
    //             // ua = u0 * ua + v0 * ub
    //             // ub = u1 * ua + v1 * ub
    //             lehmer_update(
    //                 &mut ua,
    //                 &mut ub,
    //                 &mut q,
    //                 &mut r,
    //                 &mut s,
    //                 &mut t,
    //                 u0,
    //                 u1,
    //                 v0,
    //                 v1,
    //                 even,
    //                 &mut ctx
    //             );
    //         } else {
    //             // Single-digit calculations failed to simulate any quotients
    //             euclid_update(
    //                 &mut a,
    //                 &mut b,
    //                 &mut ua,
    //                 &mut ub,
    //                 &mut q,
    //                 &mut r,
    //                 &mut s,
    //                 &mut t,
    //                 &mut ctx
    //             );
    //         }
    //         b_len = b.num_bytes();
    //     }
    //
    //     if b_len > 0 {
    //         // extended Euclidean algorithm base case if `b` is a single Word
    //         let mut a_words = a.to_vec();
    //         let mut b_words = b.to_vec();
    //
    //         if a_words.len() > 1 {
    //             a_words.reverse();
    //             b_words.reverse();
    //             // `a` is longer than a single Word, so one update is needed.
    //             euclid_update(
    //                 &mut a,
    //                 &mut b,
    //                 &mut ua,
    //                 &mut ub,
    //                 &mut q,
    //                 &mut r,
    //                 &mut s,
    //                 &mut t,
    //                 &mut ctx
    //             );
    //             a_words = a.to_vec();
    //             b_words = b.to_vec();
    //         }
    //
    //         // `a` and `b` are both single words
    //         let mut a_word = a_words[0];
    //         let mut b_word = b_words[0];
    //
    //         let mut ua_word = 1u8;
    //         let mut ub_word = 0u8;
    //         let mut va = 0u8;
    //         let mut vb = 1u8;
    //         let mut even = true;
    //
    //         while b_word != 0 {
    //             let q = a_word / b_word;
    //             let r = a_word % b_word;
    //
    //             a_word = b_word;
    //             b_word = r;
    //
    //             let k = ua_word.wrapping_add(q.wrapping_mul(ub_word));
    //             ua_word = ub_word;
    //             ub_word = k;
    //
    //             let k = va.wrapping_add(q.wrapping_mul(vb));
    //             va = vb;
    //             vb = k;
    //             even = !even;
    //         }
    //
    //         t = BigNum::from_u32(ua_word as u32).unwrap();
    //         s = BigNum::from_u32(va as u32).unwrap();
    //
    //         t.set_negative(!even);
    //         s.set_negative(even);
    //
    //         let t_c = clone_bignum(&t);
    //         let s_c = clone_bignum(&s);
    //
    //         BigNumRef::checked_mul(&mut t, &t_c, &ua, &mut ctx).unwrap();
    //         BigNumRef::checked_mul(&mut s, &s_c, &ub, &mut ctx).unwrap();
    //         BigNumRef::checked_add(&mut ua, &t, &s).unwrap();
    //         a = BigNum::from_dec_str(&format!("{}", a_word)).unwrap();
    //     }
    //
    //     let mut y_c1 = BigNum::new().unwrap();
    //     let mut y_c2 = BigNum::new().unwrap();
    //     let mut y = BigNum::new().unwrap();
    //     BigNumRef::checked_mul(&mut y_c1, &self.value, &ua, &mut ctx).unwrap();
    //     if self.value.is_negative() {
    //         let is_neg = y_c1.is_negative();
    //         y_c1.set_negative(!is_neg);
    //     }
    //     BigNumRef::checked_sub(&mut y_c2, &a, &y_c1).unwrap();
    //     BigNumRef::checked_div(&mut y, &y_c2, &b, &mut ctx).unwrap();
    //
    //     if self.value.is_negative() {
    //         let is_neg = ua.is_negative();
    //         ua.set_negative(!is_neg);
    //     }
    //
    //     (OsslBigInt{ value: ua }, OsslBigInt{ value: y })
    // }

    /// Serialize to big-endian byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

/// Attempts to simulate several Euclidean update steps using leading digits of `a` and `b`.
/// It returns `u0`, `u1`, `v0`, `v1` such that `a` and `b` can be updated as:
///     a = u0 * a + v0 * b
///     b = u1 * a + v1 * b
///
/// Requirements: `a >= b` and `b.len() > 2`.
/// Since we are calculating with full words to avoid overflow, `even` (the returned bool)
/// is used to track the sign of cosequences.
/// For even iterations: `u0, v1 >= 0 && u1, v0 <= 0`
/// For odd iterations: `u0, v1 <= && u1, v0 >= 0`
// fn lehmer_simulate(a: &BigNum, b: &BigNum) -> (u8, u8, u8, u8, bool) {
//     let mut a_digits = a.to_vec();
//     let mut b_digits = b.to_vec();
//
//     a_digits.reverse();
//     b_digits.reverse();
//
//     // m >= 2
//     let m = b_digits.len();
//     // n >= m >= 2
//     let n = a_digits.len();
//
//     // extract the top word of bits from a and b
//     let h = a_digits[n - 1].leading_zeros();
//
//     let mut a1: u8 = a_digits[n - 1] << h
//         | ((a_digits[n - 2] as u16) >> (8 - h)) as u8;
//
//     // b may have implicit zero words in the high bits if the lengths differ
//     let mut a2: u8 = if n == m {
//         b_digits[n - 1] << h
//             | ((b_digits[n - 2] as u16) >> (8 - h)) as u8
//     } else if n == m + 1 {
//         ((b_digits[n - 2] as u16) >> (8 - h)) as u8
//     } else {
//         0
//     };
//
//     // odd, even tracking
//     let mut even = false;
//
//     let mut u0 = 0;
//     let mut u1 = 1;
//     let mut u2 = 0;
//
//     let mut v0 = 0;
//     let mut v1 = 0;
//     let mut v2 = 1;
//
//     // Calculate the quotient and cosequences using Collins' stopping condition.
//     while a2 >= v2 && a1.wrapping_sub(a2) >= v1 + v2 {
//         let q = a1 / a2;
//         let r = a1 % a2;
//
//         a1 = a2;
//         a2 = r;
//
//         let k = u1 + q * u2;
//         u0 = u1;
//         u1 = u2;
//         u2 = k;
//
//         let k = v1 + q * v2;
//         v0 = v1;
//         v1 = v2;
//         v2 = k;
//
//         even = !even;
//     }
//
//     (u0, u1, v0, v1, even)
// }

/// lehmer_update updates the inputs `a` and `b` such that:
///		a = u0*a + v0*b
///		b = u1*a + v1*b
/// where the signs of u0, u1, v0, v1 are given by even
/// For even == true: u0, v1 >= 0 && u1, v0 <= 0
/// For even == false: u0, v1 <= 0 && u1, v0 >= 0
/// q, r, s, t are temporary variables to avoid allocations in the multiplication
// fn lehmer_update(
//     a: &mut BigNum,
//     b: &mut BigNum,
//     q: &mut BigNum,
//     r: &mut BigNum,
//     s: &mut BigNum,
//     t: &mut BigNum,
//     u0: u8,
//     u1: u8,
//     v0: u8,
//     v1: u8,
//     even: bool,
//     ctx: &mut BigNumContext
// ) {
//     *t = BigNum::from_u32(u0 as u32).unwrap();
//     *s = BigNum::from_u32(v0 as u32).unwrap();
//     t.set_negative(!even);
//     s.set_negative(even);
//
//     let t_c = clone_bignum(t);
//     let s_c = clone_bignum(s);
//     BigNumRef::checked_mul(t, &t_c, a, ctx).unwrap();
//     BigNumRef::checked_mul(s, &s_c, b, ctx).unwrap();
//
//     *r = BigNum::from_u32(u1 as u32).unwrap();
//     *q = BigNum::from_u32(v1 as u32).unwrap();
//     q.set_negative(!even);
//     r.set_negative(even);
//
//     let r_c = clone_bignum(r);
//     let q_c = clone_bignum(q);
//
//     BigNumRef::checked_mul(r, &r_c, a, ctx).unwrap();
//     BigNumRef::checked_mul(q, &q_c, b, ctx).unwrap();
//
//     BigNumRef::checked_add(a, t, s).unwrap();
//     BigNumRef::checked_add(b, r, q).unwrap();
// }

/// euclid_update performs a single step of the Euclidean GCD algorithm
/// it also updates the cosequence ua, ub
// fn euclid_update(
//     a: &mut BigNum,
//     b: &mut BigNum,
//     ua: &mut BigNum,
//     ub: &mut BigNum,
//     q: &mut BigNum,
//     r: &mut BigNum,
//     s: &mut BigNum,
//     t: &mut BigNum,
//     ctx: &mut BigNumContext,
// ) {
//     BigNumRef::div_rem(q, r, a, b, ctx).unwrap();
//
//     let a_r = clone_bignum(a);
//     core::mem::swap(a, b);
//     core::mem::swap(b, r);
//     *r = a_r;
//
//     // ua, ub = ub, ua - q * ub
//     *t = clone_bignum(ub);
//
//     BigNumRef::checked_mul(s, ub, q, ctx).unwrap();
//     BigNumRef::checked_sub(ub, ua, s).unwrap();
//     *ua = clone_bignum(t);
// }
//
// fn bignum_to_digits(x: &BigNum) -> Vec<u32> {
//     let mut result = Vec::new();
//     let x_bytes = x.to_vec();
//     let mut iter = x_bytes.rchunks_exact(4);
//     let mut chunk = iter.next();
//
//     while chunk.is_some() {
//         // Okay to use unwrap here since Option is checked by `while` statement
//         let item = chunk.unwrap();
//         let i = u32::from_be_bytes(*array_ref![item, 0, 4]);
//         result.push(i);
//         chunk = iter.next();
//     }
//     let item = iter.remainder();
//     if item.len() > 0 {
//         let mut r = [0u8; 4];
//         r[(4 - item.len())..].copy_from_slice(item);
//         result.push(u32::from_be_bytes(r));
//     }
//     result.reverse();
//     result
// }

impl std::iter::Product<OsslBigInt> for OsslBigInt {
    fn product<I: Iterator<Item=OsslBigInt>>(iter: I) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut value = BigNum::from_u32(1u32).unwrap();
        for i in iter {
            let i_c = clone_bignum(&value);
            BigNumRef::checked_mul(&mut value, &i.value, &i_c, &mut ctx).unwrap();
        }
        Self { value }
    }
}

impl<'a> std::iter::Product<&'a OsslBigInt> for OsslBigInt {
    fn product<I: Iterator<Item=&'a OsslBigInt>>(iter: I) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut value = BigNum::from_u32(1u32).unwrap();
        for i in iter {
            let i_c = clone_bignum(&value);
            BigNumRef::checked_mul(&mut value, &i.value, &i_c, &mut ctx).unwrap();
        }
        Self { value }
    }
}

impl std::iter::Sum<OsslBigInt> for OsslBigInt {
    fn sum<I: Iterator<Item=OsslBigInt>>(iter: I) -> Self {
        let mut value = BigNum::new().unwrap();
        for i in iter {
            let i_c = clone_bignum(&value);
            BigNumRef::checked_add(&mut value, &i.value, &i_c).unwrap();
        }
        Self { value }
    }
}

impl<'a> std::iter::Sum<&'a OsslBigInt> for OsslBigInt {
    fn sum<I: Iterator<Item=&'a OsslBigInt>>(iter: I) -> Self {
        let mut value = BigNum::new().unwrap();
        for i in iter {
            let i_c = clone_bignum(&value);
            BigNumRef::checked_add(&mut value, &i.value, &i_c).unwrap();
        }
        Self { value }
    }
}

impl Zeroize for OsslBigInt {
    fn zeroize(&mut self) {
        self.value.clear();
    }
}

impl TryFrom<&[u8]> for OsslBigInt {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self { value: BigNum::from_slice(data)? })
    }
}

impl FromStr for OsslBigInt {
    type Err = AccumulatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self { value: BigNum::from_dec_str(s)? })
    }
}

macro_rules! from_impl {
    ($ty:ty) => {
        impl From<$ty> for OsslBigInt {
            fn from(value: $ty) -> Self {
                Self { value: BigNum::from_dec_str(&format!("{}", value)).unwrap() }
            }
        }
    };
}
macro_rules! ops_impl {
    ($t:ident, $ts:ident, $f:ident, $fs:ident,$i:ident, $is:ident) => {
        impl $t for OsslBigInt {
            type Output = OsslBigInt;

            fn $f(self, rhs: Self::Output) -> Self::Output {
                self.$i(&rhs)
            }
        }

        impl<'a, 'b> $t<&'b OsslBigInt> for &'a OsslBigInt {
            type Output = OsslBigInt;

            fn $f(self, rhs: &'b Self::Output) -> Self::Output {
                self.$i(rhs)
            }
        }

        impl $ts for OsslBigInt {
            fn $fs(&mut self, rhs: OsslBigInt) {
                self.$is(&rhs)
            }
        }

        impl $ts<&OsslBigInt> for OsslBigInt {
            fn $fs(&mut self, rhs: &OsslBigInt) {
                self.$is(rhs)
            }
        }
    };
}

impl From<Vec<u8>> for OsslBigInt {
    fn from(value: Vec<u8>) -> Self {
        Self { value: BigNum::from_slice(value.as_slice()).unwrap() }
    }
}

impl Into<Vec<u8>> for OsslBigInt {
    fn into(self) -> Vec<u8> {
        self.value.to_vec()
    }
}

impl From<&str> for OsslBigInt {
    fn from(value: &str) -> Self {
        Self { value: BigNum::from_dec_str(value).unwrap() }
    }
}

impl From<u32> for OsslBigInt {
    fn from(value: u32) -> Self {
        Self { value: BigNum::from_u32(value).unwrap() }
    }
}

from_impl!(u64);
from_impl!(u16);
from_impl!(u8);
from_impl!(i64);
from_impl!(i32);
from_impl!(i16);
from_impl!(i8);

ops_impl!(Add, AddAssign, add, add_assign, add_, add_assign_);
ops_impl!(Sub, SubAssign, sub, sub_assign, sub_, sub_assign_);
ops_impl!(Mul, MulAssign, mul, mul_assign, mul_, mul_assign_);
ops_impl!(Div, DivAssign, div, div_assign, div_, div_assign_);
ops_impl!(Rem, RemAssign, rem, rem_assign, rem_, rem_assign_);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInteger;

    // #[test]
    // fn test_bignum_to_digits() {
    //     let a = BigNum::from_dec_str("170141183460469231731687303715884181001").unwrap();
    //     let b = bignum_to_digits(&a);
    //     assert_eq!(b.len(), 4);
    //     let a_bytes = a.to_vec();
    //     let a_digits: Vec<u32> = a_bytes.chunks(4).map(|c| u32::from_be_bytes(*array_ref![c, 0, 4])).collect();
    //     assert_eq!(b, a_digits);
    //     let a = BigNum::from_dec_str("18917862361804955457548714727714267128195783").unwrap();
    //     let b = bignum_to_digits(&a);
    //     assert_eq!(b.len(), 5);
    //     let a_bytes = a.to_vec();
    //     let a_digits: Vec<u32> = a_bytes[2..].chunks(4).map(|c| u32::from_be_bytes(*array_ref![c, 0, 4])).collect();
    //     assert_eq!(b[1..], a_digits[..]);
    //     assert_eq!(55594, b[0]);
    //     let a = BigNum::from_dec_str("8890919903463260501").unwrap();
    //     let b = bignum_to_digits(&a);
    //     assert_eq!(b.len(), 2);
    //     let a_bytes = a.to_vec();
    //     let a_digits: Vec<u32> = a_bytes.chunks(4).map(|c| u32::from_be_bytes(*array_ref![c, 0, 4])).collect();
    //     assert_eq!(b, a_digits);
    // }

    #[test]
    fn test_bezouts_coefficients() {
        let a = OsslBigInt::from(31);
        let b = OsslBigInt::from(37);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(gcdres.a, OsslBigInt::from(6));
        assert_eq!(gcdres.b, OsslBigInt::from(-5));

        // let (x1, y1) = a.lehmer_gcd(&b);
        // assert_eq!(x, x1);
        // assert_eq!(y, y1);

        let a = OsslBigInt::from(8890919903463260501u64);
        let b = OsslBigInt::from(4108249713441620807u64);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, OsslBigInt::from(1));
        // let (x1, y1) = a.lehmer_gcd(&b);
        // assert_eq!(x, x1);
        // assert_eq!(y, y1);

        let a = OsslBigInt::from("59066688664129022771864664899854388241934199");
        let b = OsslBigInt::from("37835724723609910915097429455428534256391567");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, OsslBigInt::from(1));

        let a = OsslBigInt::from("63156515965705215668198135979702445890399855958342988288023717346298762458519");
        let b = OsslBigInt::from("88222503113609549383110571557868679926843894352175049520163164425194315455087");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, OsslBigInt::from(1));

        let a = OsslBigInt::from("110422610948286709138485492482935635638264750009600299725452243283436733720392246059063491803632880734581205803055181800903760038310736506503680688628574356141048683956939580954585993563187988670440898390629796365318330488774232968384366277613928493883799406085796171388069092509126205421481829768092907910223");
        let b = OsslBigInt::from("144752716042106469974249706528521998938152502128562582443810766701147824209476422616749732877677665050640762537307121309778249083244222621926550031718490338251582230555954033385425427868823341471827035756696835501952242590639149948825184284419723029518177154885138979259190707216104403774189295861447177485051");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, OsslBigInt::from(1));
    }

    #[test]
    fn test_product() {
        let values = vec![BigInteger::from(2u32), BigInteger::from(3u32)];
        let res: BigInteger = values.iter().product();
        assert_eq!(res, BigInteger::from(6u32));
    }
}