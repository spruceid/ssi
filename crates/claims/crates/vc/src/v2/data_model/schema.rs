use super::Identified;

/// Value of the [`credential_schemas`](super::Credential::credential_schemas)
/// property enforcing a specific structure on a given collection of data.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
pub trait Schema: Identified {
    /// Type of data schema.
    fn types(&self) -> &[String];
}

impl Schema for std::convert::Infallible {
    fn types(&self) -> &[String] {
        unreachable!()
    }
}
