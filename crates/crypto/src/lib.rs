#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod algorithm;
pub mod hashes;
pub mod signatures;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
