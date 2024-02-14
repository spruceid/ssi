use ssi_jwt::JWTClaims;

use super::json::JsonCredential;

#[derive(Debug, thiserror::Error)]
pub enum JwtVcDecodeError {
    #[error("missing credential value")]
    MissingCredential,

    #[error("unexpected credential value (found {0}, expected object)")]
    UnexpectedCredentialValue(json_syntax::Kind),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(#[from] json_syntax::DeserializeError),
}

pub fn decode_jwt_vc<T>(mut jwt: JWTClaims) -> Result<T, JwtVcDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    match jwt.verifiable_credential.take() {
        Some(json_syntax::Value::Object(mut vc)) => {
            transform_jwt_specific_headers(jwt, &mut vc);
            Ok(json_syntax::from_value(json_syntax::Value::Object(vc))?)
        }
        Some(v) => Err(JwtVcDecodeError::UnexpectedCredentialValue(v.kind())),
        None => Err(JwtVcDecodeError::MissingCredential),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwtVpDecodeError {
    #[error("missing presentation value")]
    MissingPresentation,

    #[error("unexpected presentation value (found {0}, expected object)")]
    UnexpectedPresentationValue(json_syntax::Kind),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(#[from] json_syntax::DeserializeError),
}

pub fn decode_jwt_vp<T>(mut jwt: JWTClaims) -> Result<T, JwtVpDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    match jwt.verifiable_presentation.take() {
        Some(json_syntax::Value::Object(mut vp)) => {
            transform_jwt_specific_headers(jwt, &mut vp);
            Ok(json_syntax::from_value(json_syntax::Value::Object(vp))?)
        }
        Some(v) => Err(JwtVpDecodeError::UnexpectedPresentationValue(v.kind())),
        None => Err(JwtVpDecodeError::MissingPresentation),
    }
}

fn transform_jwt_specific_headers(jwt: JWTClaims, target: &mut json_syntax::Object) {
    // if let Some(exp) = jwt.expiration_time {
    //     todo!()
    // }

    // if let Some(iss) = jwt.issuance_date {
    //     todo!()
    // }

    // if let Some(nbf) = jwt.not_before {
    //     todo!()
    // }

    // if let Some(sub) = jwt.subject {
    //     todo!()
    // }

    // if let Some(jti) = jwt.jwt_id {
    //     todo!()
    // }
}

impl JsonCredential {
    pub fn decode_jwt(jwt: JWTClaims) -> Result<Self, JwtVcDecodeError> {
        decode_jwt_vc(jwt)
    }
}
