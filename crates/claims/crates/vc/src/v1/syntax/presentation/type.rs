use crate::{
    syntax::{RequiredType, TypeSerializationPolicy, Types},
    v1::VERIFIABLE_PRESENTATION_TYPE,
};

pub struct PresentationType;

impl RequiredType for PresentationType {
    const REQUIRED_TYPE: &'static str = VERIFIABLE_PRESENTATION_TYPE;
}

impl TypeSerializationPolicy for PresentationType {
    const PREFER_ARRAY: bool = false;
}

pub type JsonPresentationTypes<T = ()> = Types<PresentationType, T>;
