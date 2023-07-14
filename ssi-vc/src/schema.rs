use crate::{Credential, CredentialSchema};
use async_trait::async_trait;
use boon::{Compiler, Draft, Schemas};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_core::uri::URI;
use ssi_dids::did_resolve::DIDResolver;
use ssi_json_ld::ContextLoader;
use ssi_ldp::VerificationResult;
use thiserror::Error;

#[allow(clippy::upper_case_acronyms)]

/// Maximum size of a schema loaded using [`load_schema`].
pub const MAX_RESPONSE_LENGTH: usize = 2097152; // 2MB

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Credential Schema object for use in a Verifiable Credential.
/// <http://www.imsglobal.org/spec/vccs/v1p0/#credentialschema>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OneEdTechJsonSchemaValidator2019 {
    /// URL for schema information of the verifiable credential
    pub id: URI,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CredentialSchema for OneEdTechJsonSchemaValidator2019 {
    /// Validate a credential's revocation status according to [Revocation List 2020](https://w3c-ccg.github.io/vc-status-rl-2020/#validate-algorithm).
    async fn check(
        &self,
        credential: &Credential,
        _resolver: &dyn DIDResolver,
        _context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let result = VerificationResult::new();

        // Check the schema URL before attempting to load it.
        match self.id.as_str().split_once(':') {
            Some(("https", _)) => (),
            // TODO: an option to allow HTTP?
            // TODO: load from DID URLs?
            Some((_scheme, _)) => return result.with_error(format!("Invalid schema: {}", self.id)),
            _ => return result.with_error(format!("Invalid schema id: {}", self.id)),
        }

        let credential_schema = match load_schema(&self.id.as_str()).await {
            Ok(schema) => schema,
            Err(e) => {
                return result.with_error(format!("Unable to fetch credential schema: {}", e));
            }
        };

        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();

        compiler.set_default_draft(Draft::V2019_09);

        match compiler.add_resource(self.id.as_str(), credential_schema) {
            Ok(_) => (),
            Err(e) => {
                return result.with_error(format!("Unable to add schema to compiler: {}", e));
            }
        }

        let schema_index = match compiler.compile(self.id.as_str(), &mut schemas) {
            Ok(index) => index,
            Err(e) => {
                return result.with_error(format!("Unable to compile schema: {}", e));
            }
        };

        let value_credential = match serde_json::to_value(credential) {
            Ok(credential) => credential,
            Err(e) => {
                return result.with_error(format!("Unable to convert credential to JSON: {}", e));
            }
        };

        match schemas.validate(&value_credential, schema_index) {
            Ok(_) => (),
            Err(e) => {
                return result.with_error(format!("Schema validation error: {}", e));
            }
        }

        result
    }
}

#[derive(Error, Debug)]
pub enum LoadResourceError {
    #[error("Error building HTTP client: {0}")]
    Build(reqwest::Error),
    #[error("Error sending HTTP request: {0}")]
    Request(reqwest::Error),
    #[error("Parse error: {0}")]
    Response(String),
    #[error("Not found")]
    NotFound,
    #[error("HTTP error: {0}")]
    HTTP(String),
    /// The resource is larger than an expected/allowed maximum size.
    #[error("Resource is too large: {size}, expected maximum: {max}")]
    TooLarge {
        /// The size of the resource so far, in bytes.
        size: usize,
        /// Maximum expected size of the resource, in bytes.
        ///
        /// e.g. [`MAX_RESPONSE_LENGTH`]
        max: usize,
    },
    /// Unable to convert content-length header value.
    #[error("Unable to convert content-length header value")]
    ContentLengthConversion(#[source] std::num::TryFromIntError),
}

async fn load_resource(url: &str) -> Result<Vec<u8>, LoadResourceError> {
    #[cfg(test)]
    match url {
        crate::tests::EXAMPLE_CREDENTIAL_SCHEMA_URL => {
            return Ok(crate::tests::EXAMPLE_CREDENTIAL_SCHEMA.to_vec());
        }
        _ => {}
    }
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static(USER_AGENT),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(LoadResourceError::Build)?;
    let accept = "application/json".to_string();
    let resp = client
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .map_err(LoadResourceError::Request)?;
    if let Err(err) = resp.error_for_status_ref() {
        if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            return Err(LoadResourceError::NotFound);
        }
        return Err(LoadResourceError::HTTP(err.to_string()));
    }
    #[allow(unused_variables)]
    let content_length_opt = if let Some(content_length) = resp.content_length() {
        let len =
            usize::try_from(content_length).map_err(LoadResourceError::ContentLengthConversion)?;
        if len > MAX_RESPONSE_LENGTH {
            // Fail early if content-length header indicates body is too large.
            return Err(LoadResourceError::TooLarge {
                size: len,
                max: MAX_RESPONSE_LENGTH,
            });
        }
        Some(len)
    } else {
        None
    };
    #[cfg(target_arch = "wasm32")]
    {
        // Reqwest's WASM backend doesn't offer streamed/chunked response reading.
        // So we cannot check the response size while reading the response here.
        // Relevant issue: https://github.com/seanmonstar/reqwest/issues/1234
        // Instead, we hope that the content-length is correct, read the body all at once,
        // and apply the length check afterwards, for consistency.
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LoadResourceError::Response(e.to_string()))?
            .to_vec();
        if bytes.len() > MAX_RESPONSE_LENGTH {
            return Err(LoadResourceError::TooLarge {
                size: bytes.len(),
                max: MAX_RESPONSE_LENGTH,
            });
        }
        Ok(bytes)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // For non-WebAssembly, read the response up to the allowed maximimum size.
        let mut bytes = if let Some(len) = content_length_opt {
            Vec::with_capacity(len)
        } else {
            Vec::new()
        };
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| LoadResourceError::Response(e.to_string()))?
        {
            let len = bytes.len() + chunk.len();
            if len > MAX_RESPONSE_LENGTH {
                return Err(LoadResourceError::TooLarge {
                    size: len,
                    max: MAX_RESPONSE_LENGTH,
                });
            }
            bytes.append(&mut chunk.to_vec());
        }
        Ok(bytes)
    }
}

#[derive(Error, Debug)]
pub enum LoadSchemaError {
    #[error("Unable to load resource: {0}")]
    Load(#[from] LoadResourceError),
    #[error("Error reading HTTP response: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Fetch a schema from a HTTP(S) URL.
/// The resulting schema is not yet validated or verified.
pub async fn load_schema(url: &str) -> Result<Value, LoadSchemaError> {
    let data = load_resource(url).await?;
    let schema: Value = serde_json::from_slice(&data)?;

    Ok(schema)
}
