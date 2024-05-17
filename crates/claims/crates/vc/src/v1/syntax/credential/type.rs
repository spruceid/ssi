use crate::{
    syntax::{RequiredType, TypeSerializationPolicy, Types},
    v1::VERIFIABLE_CREDENTIAL_TYPE,
};

pub struct CredentialType;

impl RequiredType for CredentialType {
    const REQUIRED_TYPE: &'static str = VERIFIABLE_CREDENTIAL_TYPE;
}

impl TypeSerializationPolicy for CredentialType {
    const PREFER_ARRAY: bool = true;
}

pub type JsonCredentialTypes<T = ()> = Types<CredentialType, T>;
