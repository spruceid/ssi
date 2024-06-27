use crate::Identified;

/// Integrity metadata about each resource referenced by the verifiable
/// credential.
pub trait RelatedResource: Identified {
    fn digest_sri(&self) -> &str;
}

impl RelatedResource for std::convert::Infallible {
    fn digest_sri(&self) -> &str {
        unreachable!()
    }
}
