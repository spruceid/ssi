use iref::Uri;

/// Refresh Service.
///
/// See: <https://www.w3.org/TR/vc-data-model//#refreshing>
pub trait RefreshService {
    fn id(&self) -> &Uri;

    fn type_(&self) -> &str;
}

impl RefreshService for std::convert::Infallible {
    fn id(&self) -> &Uri {
        unreachable!()
    }

    fn type_(&self) -> &str {
        unreachable!()
    }
}
