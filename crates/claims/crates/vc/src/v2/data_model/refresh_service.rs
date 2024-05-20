/// Refresh Service.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#refreshing>
pub trait RefreshService {
    fn type_(&self) -> &str;
}

impl RefreshService for std::convert::Infallible {
    fn type_(&self) -> &str {
        unreachable!()
    }
}
