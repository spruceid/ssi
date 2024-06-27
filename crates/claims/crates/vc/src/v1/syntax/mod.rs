//! Syntaxes for the VC data model.
//! JSON syntax for Credentials and Presentations.
use super::V1;

mod credential;
mod presentation;

pub use credential::*;
pub use presentation::*;

pub type Context<C = ()> = crate::syntax::Context<V1, C>;
