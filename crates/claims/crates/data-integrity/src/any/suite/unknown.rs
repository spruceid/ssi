use ssi_data_integrity_core::Type;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnknownSuite {
    pub type_: Type,
}

impl UnknownSuite {
    pub fn new(type_: Type) -> Self {
        Self { type_ }
    }
}
