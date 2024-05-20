use super::MaybeIdentified;

/// Value of the [`credential_status`](super::Credential::credential_status)
/// property for the discovery of information related to the status of a
/// verifiable credential, such as whether it is suspended or revoked.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#status>
pub trait Status: MaybeIdentified {
    /// Type of status information expressed by the object.
    fn types(&self) -> &[String];
}

impl Status for std::convert::Infallible {
    fn types(&self) -> &[String] {
        unreachable!()
    }
}
