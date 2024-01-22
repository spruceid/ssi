use sidetree::SidetreeClient;

mod ion;
pub mod sidetree;

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub use ion::ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;
