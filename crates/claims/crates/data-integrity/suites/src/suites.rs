#[cfg(feature = "w3c")]
mod w3c;
#[cfg(feature = "w3c")]
pub use w3c::*;

#[cfg(feature = "dif")]
mod dif;
#[cfg(feature = "dif")]
#[allow(unused_imports)]
pub use dif::*;

#[cfg(any(
    feature = "aleo",
    feature = "ethereum",
    feature = "tezos",
    feature = "solana"
))]
mod unspecified;

#[cfg(any(
    feature = "aleo",
    feature = "ethereum",
    feature = "tezos",
    feature = "solana"
))]
#[allow(unused_imports)]
pub use unspecified::*;

#[allow(unused_macros)]
macro_rules! try_from_type {
    {
        $(
            $(#[cfg($($t:tt)*)])?
            $suite:ident
        ),*
    } => {
        $(
            $(#[cfg($($t)*)])?
            impl TryFrom<ssi_data_integrity_core::Type> for $suite {
                type Error = ssi_data_integrity_core::UnsupportedProofSuite;

                fn try_from(value: ssi_data_integrity_core::Type) -> Result<Self, Self::Error> {
                    let suite = $suite;

                    if value == <$suite as ssi_data_integrity_core::StandardCryptographicSuite>::type_(&suite) {
                        Ok($suite)
                    } else {
                        Err(ssi_data_integrity_core::UnsupportedProofSuite::Compact(value))
                    }
                }
            }
        )*
    };
}

#[allow(unused_imports)]
pub(crate) use try_from_type;
