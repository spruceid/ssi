use failure::{Backtrace, Context, Fail};

/// The error types
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum AccumulatorErrorKind {
    /// Type cannot be converted to an BigInteger
    #[fail(display = "Type cannot be converted to BigInteger")]
    InvalidType,
    /// When trying to add a member that already exists in the accumulator
    #[fail(display = "The value supplied already exists in the accumulator")]
    DuplicateValueSupplied,
    /// When trying to create a witness to a value not in the accumulator
    /// or when trying to remove an invalid value from the accumulator
    #[fail(display = "Member is not currently in the accumulator")]
    InvalidMemberSupplied,
    /// An incorrect number of bytes was supplied when trying to deserialize from bytes
    #[fail(display = "Invalid bytes supplied when deserializing")]
    SerializationError,
}

/// Error wrapper to add context and backtrace
#[derive(Debug)]
pub struct AccumulatorError {
    inner: Context<AccumulatorErrorKind>,
}

impl Fail for AccumulatorError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl AccumulatorError {
    /// Convert from a kind with msg string
    pub fn from_msg<D>(kind: AccumulatorErrorKind, msg: D) -> AccumulatorError
        where
            D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        AccumulatorError {
            inner: Context::new(msg).context(kind),
        }
    }

    /// Get the inner error kind
    pub fn kind(&self) -> AccumulatorErrorKind {
        *self.inner.get_context()
    }
}

impl std::fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut first = true;

        for cause in <dyn Fail>::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }

        Ok(())
    }
}

impl From<Context<AccumulatorErrorKind>> for AccumulatorError {
    fn from(inner: Context<AccumulatorErrorKind>) -> Self {
        AccumulatorError { inner }
    }
}

impl From<AccumulatorErrorKind> for AccumulatorError {
    fn from(err: AccumulatorErrorKind) -> Self {
        AccumulatorError::from_msg(err, "")
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for AccumulatorError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        AccumulatorError::from_msg(AccumulatorErrorKind::InvalidType, err.errors().iter().map(|e| e.reason().unwrap_or("")).collect::<Vec<&str>>().join(","))
    }
}

#[cfg(feature = "rust-gmp")]
impl From<gmp::mpz::ParseMpzError> for AccumulatorError {
    fn from(err: gmp::mpz::ParseMpzError) -> Self {
        AccumulatorError::from_msg(AccumulatorErrorKind::InvalidType, format!("{:?}", err))
    }
}

#[cfg(feature = "bi-rust")]
impl From<num_bigint::ParseBigIntError> for AccumulatorError {
    fn from(err: num_bigint::ParseBigIntError) -> Self {
        AccumulatorError::from_msg(AccumulatorErrorKind::InvalidType, format!("{:?}", err))
    }
}
