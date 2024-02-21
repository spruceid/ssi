use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

use super::ObjectWithId;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Issuer {
    Uri(UriBuf),
    Object(ObjectWithId),
}

impl Issuer {
    pub fn id(&self) -> &Uri {
        match self {
            Self::Uri(uri) => uri,
            Self::Object(object) => &object.id,
        }
    }
}

impl From<UriBuf> for Issuer {
    fn from(value: UriBuf) -> Self {
        Self::Uri(value)
    }
}

impl crate::Issuer for Issuer {
    fn id(&self) -> &Uri {
        self.id()
    }
}
