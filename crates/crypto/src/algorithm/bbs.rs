pub use ssi_bbs::*;

#[derive(Debug, Clone)]
pub struct BbsInstance(pub Box<SignatureParameters>);
