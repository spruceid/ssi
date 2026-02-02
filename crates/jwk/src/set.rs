use serde::{Deserialize, Serialize};

use super::JWK;

/// JWK Set.
///
/// See: <https://www.rfc-editor.org/rfc/rfc7517#section-5>
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwkSet {
    /// Keys.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7517#section-5.1>
    pub keys: Vec<JWK>,
}
