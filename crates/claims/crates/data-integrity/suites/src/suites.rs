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
