use iref::{Uri, UriBuf};

/// Integrity metadata about each resource referenced by the verifiable
/// credential.
pub struct RelatedResource {
    pub id: UriBuf,

    pub digest_sri: String,
}

impl crate::Identified for RelatedResource {
    fn id(&self) -> &Uri {
        &self.id
    }
}

impl crate::v2::RelatedResource for RelatedResource {
    fn digest_sri(&self) -> &str {
        &self.digest_sri
    }
}
