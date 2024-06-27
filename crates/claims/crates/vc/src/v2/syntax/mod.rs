mod language;
pub use language::*;

mod related_resource;
pub use related_resource::*;

mod credential;
pub use credential::*;

mod presentation;
pub use presentation::*;

use super::V2;

pub type Context<C = ()> = crate::syntax::Context<V2, C>;
