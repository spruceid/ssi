use iref::Uri;

mod hashing;
pub use hashing::Eip712Hashing;

mod signature;
pub use signature::*;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub types: Option<ssi_eip712::Types>,
    pub primary_type: Option<ssi_eip712::StructName>,
    pub domain: Option<ssi_eip712::Value>,
    pub message: ssi_eip712::Struct,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidInput {
    #[error(transparent)]
    TypeGenerationFailed(#[from] ssi_eip712::TypesGenerationError),

    #[error("invalid message")]
    InvalidMessage,

    #[error("found a `proof` value in the message")]
    FoundProofValue,
}

impl Input {
    pub fn try_into_typed_data(
        mut self,
        proof_configuration: &impl serde::Serialize,
    ) -> Result<ssi_eip712::TypedData, InvalidInput> {
        let domain = self.domain.unwrap_or_else(Self::default_domain);
        let primary_type = self.primary_type.unwrap_or_else(Self::default_primary_type);

        self.message.insert(
            "proof".to_string(),
            ssi_eip712::to_value(proof_configuration).unwrap(),
        );

        let message = ssi_eip712::Value::Struct(self.message);

        let types = match self.types {
            Some(types) => types,
            None => ssi_eip712::Types::generate(
                &message,
                primary_type.clone(),
                Self::default_domain_type(),
            )?,
        };

        let result = ssi_eip712::TypedData {
            types,
            primary_type,
            domain,
            message,
        };

        Ok(result)
    }

    pub fn default_domain() -> ssi_eip712::Value {
        ssi_eip712::Value::Struct(
            [(
                "name".to_string(),
                ssi_eip712::Value::String("EthereumEip712Signature2021".to_string()),
            )]
            .into_iter()
            .collect(),
        )
    }

    pub fn default_domain_type() -> ssi_eip712::TypeDefinition {
        ssi_eip712::TypeDefinition::new(vec![ssi_eip712::MemberVariable::new(
            "name".to_string(),
            ssi_eip712::TypeRef::String,
        )])
    }

    pub fn default_primary_type() -> ssi_eip712::StructName {
        "Document".into()
    }
}

/// Errors that can occur while fetching remote EIP712 type definitions.
#[derive(Debug, thiserror::Error)]
pub enum TypesFetchError {
    /// Error for applications that do not support remote types.
    ///
    /// This is the error always returned by the `()` implementation of
    /// `TypesProvider`.
    #[error("remote EIP712 types are not supported")]
    Unsupported,
}

/// Type providing remote EIP712 type definitions from an URI.
///
/// A default implementation is provided for the `()` type that always return
/// `TypesFetchError::Unsupported`.
pub trait TypesProvider {
    /// Fetches the type definitions located behind the given `uri`.
    ///
    /// This is an asynchronous function returning a `Self::Fetch` future that
    /// resolves into ether the EIP712 [`Types`](ssi_eip712::Types) or an error
    /// of type `TypesFetchError`.
    #[allow(async_fn_in_trait)]
    async fn fetch_types(&self, uri: &Uri) -> Result<ssi_eip712::Types, TypesFetchError>;
}

/// Simple EIP712 loader implementation that always return
/// `TypesFetchError::Unsupported`.
impl TypesProvider for () {
    async fn fetch_types(&self, _uri: &Uri) -> Result<ssi_eip712::Types, TypesFetchError> {
        Err(TypesFetchError::Unsupported)
    }
}
