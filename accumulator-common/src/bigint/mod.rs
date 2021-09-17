/// Use Big Integer implementation backed by OpenSSL BigNum
#[cfg(feature = "openssl")]
pub mod ossl;
/// Use Big Integer implementation backed by GMP Mpz
#[cfg(feature = "rust-gmp")]
pub mod mpz;
/// Use Big Integer implementation backed by rust's num-bigint
#[cfg(feature = "bi-rust")]
pub mod rust;

/// The result from running extended euclid algorithm
#[derive(Debug, Default)]
pub struct GcdResult {
    /// The greatest common divisor
    pub value: BigInteger,
    /// Bézout coefficient `a`
    pub a: BigInteger,
    /// Bézout coefficient `b`
    pub b: BigInteger
}

#[cfg(feature = "openssl")]
pub use ossl::OsslBigInt as BigInteger;
#[cfg(feature = "rust-gmp")]
pub use mpz::MpzBigInt as BigInteger;
#[cfg(feature = "bi-rust")]
pub use rust::RustBigInt as BigInteger;

