//! Syntaxes for the VC data model.
pub mod json;
mod jwt;

pub use json::{JsonCredential, JsonPresentation};
pub use jwt::*;