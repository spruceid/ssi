use super::GcdResult;
use crate::error::AccumulatorError;
use gmp::{
    mpz::{Mpz, ProbabPrimeResult},
    rand::RandState,
};
use std::{
    ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Div, DivAssign, Rem, RemAssign},
    cmp::Ordering,
    convert::TryFrom,
    str::FromStr
};
use zeroize::Zeroize;

#[inline]
fn clone_mpz(b: &Mpz) -> Mpz {
    let mut t = Mpz::new();
    Mpz::clone_from(&mut t, b);
    t
}

/// A Big Integer Implementation backed by OpenSSL Mpz
#[derive(Debug)]
pub struct MpzBigInt {
    pub(crate) value: Mpz,
}

impl std::fmt::Display for MpzBigInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MpzBigInt {{ value: {} }}", self.value.to_str_radix(10))
    }
}

impl Clone for MpzBigInt {
    fn clone(&self) -> Self {
        Self {
            value: clone_mpz(&self.value),
        }
    }
}

impl PartialEq for MpzBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for MpzBigInt {}

impl PartialOrd for MpzBigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl Ord for MpzBigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl Default for MpzBigInt {
    fn default() -> Self {
        Self { value: Mpz::new() }
    }
}

impl MpzBigInt {
    /// Used by the std::ops::Add methods
    fn add_(&self, rhs: &Self) -> Self {
        Self { value: &self.value + &rhs.value }
    }

    /// Used by the std::ops::AddAssign methods
    fn add_assign_(&mut self, rhs: &Self) {
        self.value += &rhs.value;
    }

    /// Used by the std::ops::Sub methods
    fn sub_(&self, rhs: &Self) -> Self {
        Self { value: &self.value - &rhs.value }
    }

    /// Used by the std::ops::SubAssign methods
    fn sub_assign_(&mut self, rhs: &Self) {
        self.value -= &rhs.value;
    }

    /// Used by the std::ops::Mul methods
    fn mul_(&self, rhs: &Self) -> Self {
        Self { value: &self.value * &rhs.value }
    }

    /// Used by the std::ops::MulAssign methods
    fn mul_assign_(&mut self, rhs: &Self) {
        self.value *= &rhs.value;
    }

    /// Used by the std::ops::Div methods
    fn div_(&self, rhs: &Self) -> Self {
        Self { value: &self.value / &rhs.value }
    }

    /// Used by the std::ops::DivAssign methods
    fn div_assign_(&mut self, rhs: &Self) {
        self.value /= &rhs.value;
    }

    /// Used by the std::ops::Rem methods
    fn rem_(&self, rhs: &Self) -> Self {
        Self { value: (&self.value).modulus(&rhs.value) }
    }

    /// Used by the std::ops::RemAssign methods
    fn rem_assign_(&mut self, rhs: &Self) {
        self.value = self.value.modulus(&rhs.value)
    }

    /// Compute the quotient and remainder and return both
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (q, r) = self.value.div_rem(&rhs.value);
        (Self { value: q }, Self { value: r })
    }

    /// Compute modular exponentiation and return the result
    /// result = self ^ rhs mod order
    pub fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let one = Mpz::one();
        let zero = Mpz::new();
        if exponent.value == zero {
            return Self { value: one };
        }
        if exponent.value == one {
            return self.clone();
        }

        Self { value: self.value.powm_sec(&exponent.value, &modulus.value) }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ exponent mod order
    pub fn mod_exp_assign(&mut self, exponent: &Self, modulus: &Self) {
        let one = Mpz::one();
        if exponent.value == Mpz::new() {
            self.value = one;
            return;
        } else if exponent.value == one {
            return;
        }

        self.value = self.value.powm_sec(&exponent.value, &modulus.value);
    }

    /// Compute modular square and return the result
    /// result = self ^ 2 mod order
    pub fn mod_sqr(&self, modulus: &Self) -> Self {
        Self { value: (&self.value).powm(&Mpz::from(2), &modulus.value) }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ 2 mod order
    pub fn mod_sqr_assign(&mut self, modulus: &Self) {
        self.value = self.value.powm(&Mpz::from(2), &modulus.value)
    }

    /// Compute modular inverse and return the result
    /// result = self ^ -1 mod order
    pub fn mod_inverse(&self, modulus: &Self) -> Self {
        Self { value: self.value.invert(&modulus.value).unwrap() }
    }

    /// Compute modular inverse and assign it to self
    /// self = self ^ -1 mod order
    pub fn mod_inverse_assign(&mut self, modulus: &Self) {
        self.value = self.value.invert(&modulus.value).unwrap();
    }

    /// Compute modular multiplication and return the result
    /// result = self * rhs mod order
    pub fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        Self { value: (&self.value * &rhs.value).modulus(&modulus.value) }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self * rhs mod order
    pub fn mod_mul_assign(&mut self, rhs: &Self, modulus: &Self) {
       self.value = (&self.value * &rhs.value).modulus(&modulus.value);
    }

    /// Generate a prime number of `size` bits
    pub fn generate_prime(size: usize) -> Self {
        let mut rand_state = RandState::new();
        Self { value: rand_state.urandom_2exp(size as u64).nextprime() }
    }

    /// Generate a safe prime number of `size` bits
    pub fn generate_safe_prime(size: usize) -> Self {
        let mut rand_state = RandState::new();
        let three = Mpz::from(3);
        let two = Mpz::from(2);
        loop {
            let value = rand_state.urandom_2exp(size as u64).nextprime();
            if value.modulus(&three) == two  {
                return Self { value };
            }
        }
    }

    /// Generate a random value less than `self`
    pub fn rand_range(&self) -> Self {
        let mut rand_state = RandState::new();
        Self { value: rand_state.urandom(&self.value) }
    }

    /// Determine if `self` is a prime number
    pub fn is_prime(&self) -> bool {
        match self.value.probab_prime(15) {
            ProbabPrimeResult::Prime | ProbabPrimeResult::ProbablyPrime => true,
            _ => false
        }
    }

    /// Computes Bézout's coefficients and returns `s` and `t`
    /// using the extended euclidean algorithm
    /// Eventually replace with lehmer's GCD, see
    /// Based on https://github.com/golang/go/blob/master/src/math/big/int.go#L612
    /// and https://github.com/dignifiedquire/num-bigint/blob/master/src/algorithms/gcd.rs#L239
    pub fn bezouts_coefficients(&self, rhs: &Self) -> GcdResult {
        let (g, s, t) = self.value.gcdext(&rhs.value);

        GcdResult {
            value: Self { value: g },
            a: Self { value: s },
            b: Self { value: t }
        }
    }

    /// The number of bits needed to represent `self`
    pub fn bits(&self) -> usize {
        self.value.bit_length()
    }

    /// Serialize to big-endian byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        Into::<Vec<u8>>::into(&self.value)
    }
}

impl std::iter::Product<MpzBigInt> for MpzBigInt {
    fn product<I: Iterator<Item=MpzBigInt>>(iter: I) -> Self {
        let mut value = Mpz::one();
        for i in iter {
            value *= &i.value;
        }
        Self { value }
    }
}

impl<'a> std::iter::Product<&'a MpzBigInt> for MpzBigInt {
    fn product<I: Iterator<Item=&'a MpzBigInt>>(iter: I) -> Self {
        let mut value =  Mpz::one();
        for i in iter {
            value *= &i.value;
        }
        Self { value }
    }
}

impl std::iter::Sum<MpzBigInt> for MpzBigInt {
    fn sum<I: Iterator<Item=MpzBigInt>>(iter: I) -> Self {
        let mut value = Mpz::new();
        for i in iter {
            value += &i.value;
        }
        Self { value }
    }
}

impl<'a> std::iter::Sum<&'a MpzBigInt> for MpzBigInt {
    fn sum<I: Iterator<Item=&'a MpzBigInt>>(iter: I) -> Self {
        let mut value = Mpz::new();
        for i in iter {
            value += &i.value;
        }
        Self { value }
    }
}

impl Zeroize for MpzBigInt {
    fn zeroize(&mut self) {
        self.value ^= &self.value.clone();
    }
}

impl TryFrom<&[u8]> for MpzBigInt {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self { value: Mpz::from(data) })
    }
}

impl FromStr for MpzBigInt {
    type Err = AccumulatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self { value: Mpz::from_str_radix(s, 10)? })
    }
}

macro_rules! from_impl {
    ($ty:ty) => {
        impl From<$ty> for MpzBigInt {
            fn from(value: $ty) -> Self {
                Self { value: Mpz::from_str_radix(&format!("{}", value), 10).unwrap() }
            }
        }
    };
}
macro_rules! ops_impl {
    ($t:ident, $ts:ident, $f:ident, $fs:ident,$i:ident, $is:ident) => {
        impl $t for MpzBigInt {
            type Output = MpzBigInt;

            fn $f(self, rhs: Self::Output) -> Self::Output {
                self.$i(&rhs)
            }
        }

        impl<'a, 'b> $t<&'b MpzBigInt> for &'a MpzBigInt {
            type Output = MpzBigInt;

            fn $f(self, rhs: &'b Self::Output) -> Self::Output {
                self.$i(rhs)
            }
        }

        impl $ts for MpzBigInt {
            fn $fs(&mut self, rhs: MpzBigInt) {
                self.$is(&rhs)
            }
        }

        impl $ts<&MpzBigInt> for MpzBigInt {
            fn $fs(&mut self, rhs: &MpzBigInt) {
                self.$is(rhs)
            }
        }
    };
}

impl From<Vec<u8>> for MpzBigInt {
    fn from(value: Vec<u8>) -> Self {
        Self { value: Mpz::from(value.as_slice()) }
    }
}

impl Into<Vec<u8>> for MpzBigInt {
    fn into(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl From<&str> for MpzBigInt {
    fn from(value: &str) -> Self {
        Self { value: Mpz::from_str_radix(value, 10).unwrap() }
    }
}

from_impl!(u64);
from_impl!(u32);
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

    #[test]
    fn test_bezouts_coefficients() {
        let a = MpzBigInt::from(31);
        let b = MpzBigInt::from(37);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(gcdres.a, MpzBigInt::from(6));
        assert_eq!(gcdres.b, MpzBigInt::from(-5));

        let a = MpzBigInt::from(8890919903463260501u64);
        let b = MpzBigInt::from(4108249713441620807u64);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, MpzBigInt::from(1));

        let a = MpzBigInt::from("59066688664129022771864664899854388241934199");
        let b = MpzBigInt::from("37835724723609910915097429455428534256391567");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, MpzBigInt::from(1));

        let a = MpzBigInt::from("63156515965705215668198135979702445890399855958342988288023717346298762458519");
        let b = MpzBigInt::from("88222503113609549383110571557868679926843894352175049520163164425194315455087");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, MpzBigInt::from(1));

        let a = MpzBigInt::from("110422610948286709138485492482935635638264750009600299725452243283436733720392246059063491803632880734581205803055181800903760038310736506503680688628574356141048683956939580954585993563187988670440898390629796365318330488774232968384366277613928493883799406085796171388069092509126205421481829768092907910223");
        let b = MpzBigInt::from("144752716042106469974249706528521998938152502128562582443810766701147824209476422616749732877677665050640762537307121309778249083244222621926550031718490338251582230555954033385425427868823341471827035756696835501952242590639149948825184284419723029518177154885138979259190707216104403774189295861447177485051");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, MpzBigInt::from(1));
    }

    #[test]
    fn test_product() {
        let values = vec![BigInteger::from(2u32), BigInteger::from(3u32)];
        let res: BigInteger = values.iter().product();
        assert_eq!(res, BigInteger::from(6u32));
    }
}