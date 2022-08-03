use super::GcdResult;
use crate::error::AccumulatorError;
use num_bigint::{BigInt, RandBigInt, ToBigInt, Sign};
use num_traits::{Zero, One, Signed, Num};
use num_integer::Integer;
use std::{
    ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Div, DivAssign, Rem, RemAssign},
    cmp::Ordering,
    convert::TryFrom,
    str::FromStr
};
use zeroize::Zeroize;

/// A Big Integer Implementation backed by OpenSSL BigNum
#[derive(Debug)]
pub struct RustBigInt {
    pub(crate) value: BigInt,
}

impl std::fmt::Display for RustBigInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RustBigInt {{ value: {} }}", self.value.to_str_radix(10))
    }
}

impl Clone for RustBigInt {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone()
        }
    }
}

impl PartialEq for RustBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for RustBigInt {}

impl PartialOrd for RustBigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl Ord for RustBigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl Default for RustBigInt {
    fn default() -> Self {
        Self { value: BigInt::zero() }
    }
}

impl RustBigInt {
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
        Self { value: &self.value % &rhs.value }
    }

    /// Used by the std::ops::RemAssign methods
    fn rem_assign_(&mut self, rhs: &Self) {
        self.value %= &rhs.value;
    }

    /// Compute the quotient and remainder and return both
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (q, r) = self.value.div_rem(&rhs.value);
        (Self { value: q }, Self { value: r })
    }

    /// Compute modular exponentiation and return the result
    /// result = self ^ rhs mod order
    pub fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        if exponent.value.is_zero() {
            return Self { value: BigInt::one() };
        }
        if exponent.value.is_one() {
            return self.clone();
        }
        let value =
        if exponent.value.is_negative() {
            let res = self.inverse(modulus);
            let exp = -&exponent.value;
            res.modpow(&exp, &modulus.value)
        } else {
            self.value.modpow(&exponent.value, &modulus.value)
        };
        Self { value }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ exponent mod order
    pub fn mod_exp_assign(&mut self, exponent: &Self, modulus: &Self) {
        if exponent.value.is_zero() {
            self.value.set_one();
        }
        if exponent.value.is_one() {
            return;
        }
        if exponent.value.is_negative() {
            let res = self.inverse(modulus);
            let exp = -&exponent.value;
            self.value = res.modpow(&exp, &modulus.value)
        } else {
            self.value = self.value.modpow(&exponent.value, &modulus.value)
        }
    }

    /// Compute modular square and return the result
    /// result = self ^ 2 mod order
    pub fn mod_sqr(&self, modulus: &Self) -> Self {
        Self { value: (&self.value * &self.value) % &modulus.value }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self ^ 2 mod order
    pub fn mod_sqr_assign(&mut self, modulus: &Self) {
        self.value = (&self.value * &self.value) % &modulus.value
    }

    /// Compute modular inverse and return the result
    /// result = self ^ -1 mod order
    pub fn mod_inverse(&self, modulus: &Self) -> Self {
        Self { value: self.inverse(modulus) }
    }

    /// Compute modular inverse and assign it to self
    /// self = self ^ -1 mod order
    pub fn mod_inverse_assign(&mut self, modulus: &Self) {
        self.value = self.inverse(modulus);
    }

    fn inverse(&self, modulus: &Self) -> BigInt {
        if modulus.value.is_zero() ||
            modulus.value.is_one() {
            panic!("Invalid modulus");
        }

        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (modulus.value.clone(), self.value.clone());

        while !new_r.is_zero() {
            let q = &r / &new_r;

            let temp_t = t.clone();
            t = new_t.clone();
            new_t = &temp_t - &q * &new_t;

            let temp_r =  r.clone();
            r = new_r.clone();
            new_r = &temp_r - &q * &new_r;
        }

        if r > BigInt::one() {
            panic!("Not invertible")
        } else if t.is_negative() {
            t += &modulus.value;
        }
        t
    }

    /// Compute modular multiplication and return the result
    /// result = self * rhs mod order
    pub fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        Self { value: (&self.value * &rhs.value) % &modulus.value }
    }

    /// Compute modular exponentiation and assign it to self
    /// self = self * rhs mod order
    pub fn mod_mul_assign(&mut self, rhs: &Self, modulus: &Self) {
        self.value = (&self.value * &rhs.value) % &modulus.value;
    }

    /// Generate a prime number of `size` bits
    pub fn generate_prime(size: usize) -> Self {
        Self { value: glass_pumpkin::prime::new(size).unwrap().to_bigint().unwrap() }
    }

    /// Generate a safe prime number of `size` bits
    pub fn generate_safe_prime(size: usize) -> Self {
        Self { value: glass_pumpkin::safe_prime::new(size).unwrap().to_bigint().unwrap() }
    }

    /// Generate a random value less than `self`
    pub fn rand_range(&self) -> Self {
        let mut rng = rand::thread_rng();
        let value = rng.gen_bigint_range(&BigInt::zero(), &self.value);
        Self { value }
    }

    /// Determine if `self` is a prime number
    pub fn is_prime(&self) -> bool {
        if self.value.is_negative() {
            return false;
        }
        glass_pumpkin::prime::check(&self.value.to_biguint().unwrap())
    }

    /// Computes Bézout's coefficients and returns `s` and `t`
    /// using the extended euclidean algorithm
    /// Eventually replace with lehmer's GCD, see
    /// Based on https://github.com/golang/go/blob/master/src/math/big/int.go#L612
    /// and https://github.com/dignifiedquire/num-bigint/blob/master/src/algorithms/gcd.rs#L239
    pub fn bezouts_coefficients(&self, rhs: &Self) -> GcdResult {
        if self.value.is_zero() && rhs.value.is_zero() {
            return GcdResult {
                value: Self::default(),
                a: Self::default(),
                b: Self::default()
            };
        }
        if self.value.is_zero() {
            return GcdResult {
                value: Self::default(),
                a: Self::default(),
                b: Self { value: BigInt::one() },
            };
        }
        if rhs.value.is_zero() {
            return GcdResult {
                value: Self::default(),
                a: Self { value: BigInt::one() },
                b: Self::default()
            };
        }

        let mut s = BigInt::zero();
        let mut old_s = BigInt::one();
        let mut t = BigInt::one();
        let mut old_t = BigInt::zero();
        let mut r = rhs.value.clone();
        let mut old_r = self.value.clone();

        while !r.is_zero() {
            let q = &old_r / &r;

            let temp_r = old_r.clone();
            old_r = r.clone();
            r = temp_r - &q * &r;

            let temp_s = old_s.clone();
            old_s = s.clone();
            s = temp_s - &q * &s;

            let temp_t = old_t.clone();
            old_t = t.clone();
            t = temp_t - &q * &t;
        }

        GcdResult {
            value: Self { value: old_r },
            a: Self { value: old_s },
            b: Self { value: old_t }
        }
    }

    /// The number of bits needed to represent `self`
    pub fn bits(&self) -> usize {
        self.value.bits() as usize
    }

    /// Serialize to big-endian byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        let (_, r) = self.value.to_bytes_be();
        r
    }
}

impl std::iter::Product<RustBigInt> for RustBigInt {
    fn product<I: Iterator<Item=RustBigInt>>(iter: I) -> Self {
        let mut value = BigInt::one();
        for i in iter {
            value *= &i.value;
        }
        Self { value }
    }
}

impl<'a> std::iter::Product<&'a RustBigInt> for RustBigInt {
    fn product<I: Iterator<Item=&'a RustBigInt>>(iter: I) -> Self {
        let mut value = BigInt::one();
        for i in iter {
            value *= &i.value;
        }
        Self { value }
    }
}

impl std::iter::Sum<RustBigInt> for RustBigInt {
    fn sum<I: Iterator<Item=RustBigInt>>(iter: I) -> Self {
        let mut value = BigInt::zero();
        for i in iter {
            value += &i.value;
        }
        Self { value }
    }
}

impl<'a> std::iter::Sum<&'a RustBigInt> for RustBigInt {
    fn sum<I: Iterator<Item=&'a RustBigInt>>(iter: I) -> Self {
        let mut value = BigInt::zero();
        for i in iter {
            value += &i.value;
        }
        Self { value }
    }
}

impl Zeroize for RustBigInt {
    fn zeroize(&mut self) {
        self.value.set_zero();
    }
}

impl TryFrom<&[u8]> for RustBigInt {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self { value: BigInt::from_bytes_be(Sign::Plus, data) })
    }
}

impl FromStr for RustBigInt {
    type Err = AccumulatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self { value: BigInt::from_str_radix(s, 10)? })
    }
}

macro_rules! from_impl {
    ($ty:ty) => {
        impl From<$ty> for RustBigInt {
            fn from(value: $ty) -> Self {
                Self { value: BigInt::from(value) }
            }
        }
    };
}
macro_rules! ops_impl {
    ($t:ident, $ts:ident, $f:ident, $fs:ident,$i:ident, $is:ident) => {
        impl $t for RustBigInt {
            type Output = RustBigInt;

            fn $f(self, rhs: Self::Output) -> Self::Output {
                self.$i(&rhs)
            }
        }

        impl<'a, 'b> $t<&'b RustBigInt> for &'a RustBigInt {
            type Output = RustBigInt;

            fn $f(self, rhs: &'b Self::Output) -> Self::Output {
                self.$i(rhs)
            }
        }

        impl $ts for RustBigInt {
            fn $fs(&mut self, rhs: RustBigInt) {
                self.$is(&rhs)
            }
        }

        impl $ts<&RustBigInt> for RustBigInt {
            fn $fs(&mut self, rhs: &RustBigInt) {
                self.$is(rhs)
            }
        }
    };
}

impl From<Vec<u8>> for RustBigInt {
    fn from(value: Vec<u8>) -> Self {
        Self { value: BigInt::from_bytes_be(Sign::Plus, value.as_slice()) }
    }
}

impl Into<Vec<u8>> for RustBigInt {
    fn into(self) -> Vec<u8> {
        let (_, r) = self.value.to_bytes_be();
        r
    }
}

impl From<&str> for RustBigInt {
    fn from(value: &str) -> Self {
        Self { value: BigInt::from_str_radix(value, 10).unwrap() }
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
        let a = RustBigInt::from(31);
        let b = RustBigInt::from(37);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(gcdres.a, RustBigInt::from(6));
        assert_eq!(gcdres.b, RustBigInt::from(-5));

        let a = RustBigInt::from(8890919903463260501u64);
        let b = RustBigInt::from(4108249713441620807u64);
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, RustBigInt::from(1));

        let a = RustBigInt::from("59066688664129022771864664899854388241934199");
        let b = RustBigInt::from("37835724723609910915097429455428534256391567");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, RustBigInt::from(1));

        let a = RustBigInt::from("63156515965705215668198135979702445890399855958342988288023717346298762458519");
        let b = RustBigInt::from("88222503113609549383110571557868679926843894352175049520163164425194315455087");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, RustBigInt::from(1));

        let a = RustBigInt::from("110422610948286709138485492482935635638264750009600299725452243283436733720392246059063491803632880734581205803055181800903760038310736506503680688628574356141048683956939580954585993563187988670440898390629796365318330488774232968384366277613928493883799406085796171388069092509126205421481829768092907910223");
        let b = RustBigInt::from("144752716042106469974249706528521998938152502128562582443810766701147824209476422616749732877677665050640762537307121309778249083244222621926550031718490338251582230555954033385425427868823341471827035756696835501952242590639149948825184284419723029518177154885138979259190707216104403774189295861447177485051");
        let gcdres = a.bezouts_coefficients(&b);
        assert_eq!(&a * &gcdres.a + &b * &gcdres.b, RustBigInt::from(1));
    }

    #[test]
    fn test_product() {
        let values = vec![BigInteger::from(2u32), BigInteger::from(3u32)];
        let res: BigInteger = values.iter().product();
        assert_eq!(res, BigInteger::from(6u32));
    }
}
