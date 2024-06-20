use std::fmt;

use chrono::{DateTime, Utc};
use ssi_jwt::ClaimSet;

#[derive(Debug, thiserror::Error)]
pub enum JwtVcDecodeError {
    #[error("unable to read claim: {0}")]
    Claim(String),

    #[error("missing credential value")]
    MissingCredential,

    #[error("unexpected credential value (found {0}, expected object)")]
    UnexpectedCredentialValue(json_syntax::Kind),

    #[error("invalid credential subject: expected object, found {0}")]
    InvalidCredentialSubject(json_syntax::Kind),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(#[from] json_syntax::DeserializeError),
}

impl JwtVcDecodeError {
    fn claim(e: impl fmt::Display) -> Self {
        Self::Claim(e.to_string())
    }
}

/// Decodes a Verifiable Credential form a JWT.
///
/// See: <https://www.w3.org/TR/vc-data-model/#json-web-token>
pub fn decode_jwt_vc_claims<T>(mut jwt: impl ClaimSet) -> Result<T, JwtVcDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let ssi_jwt::VerifiableCredential(vc) = jwt
        .try_remove()
        .map_err(JwtVcDecodeError::claim)?
        .ok_or(JwtVcDecodeError::MissingCredential)?;

    match vc {
        json_syntax::Value::Object(mut vc) => {
            decode_jwt_vc_specific_headers(jwt, &mut vc)?;
            Ok(json_syntax::from_value(json_syntax::Value::Object(vc))?)
        }
        v => Err(JwtVcDecodeError::UnexpectedCredentialValue(v.kind())),
    }
}

fn decode_jwt_vc_specific_headers(
    mut jwt: impl ClaimSet,
    target: &mut json_syntax::Object,
) -> Result<(), JwtVcDecodeError> {
    let exp = jwt
        .try_remove::<ssi_jwt::ExpirationTime>()
        .map_err(JwtVcDecodeError::claim)?;
    let iss = jwt
        .try_remove::<ssi_jwt::Issuer>()
        .map_err(JwtVcDecodeError::claim)?;
    let iat = jwt
        .try_remove::<ssi_jwt::IssuedAt>()
        .map_err(JwtVcDecodeError::claim)?
        .map(|iat| iat.0);
    let nbf = jwt
        .try_remove::<ssi_jwt::NotBefore>()
        .map_err(JwtVcDecodeError::claim)?
        .map(|nbf| nbf.0);
    let sub = jwt
        .try_remove::<ssi_jwt::Subject>()
        .map_err(JwtVcDecodeError::claim)?;
    let jti = jwt
        .try_remove::<ssi_jwt::JwtId>()
        .map_err(JwtVcDecodeError::claim)?;

    if let Some(ssi_jwt::ExpirationTime(exp)) = exp {
        let exp_date_time: chrono::LocalResult<DateTime<Utc>> = exp.into();
        if let Some(time) = exp_date_time.latest() {
            let credential_subject = target
                .get_mut_or_insert_with("credentialSubject", || json_syntax::Object::new().into());
            let kind = credential_subject.kind();

            credential_subject
                .as_object_mut()
                .ok_or(JwtVcDecodeError::InvalidCredentialSubject(kind))?
                .insert(
                    "expirationDate".into(),
                    xsd_types::DateTime::from(time).to_string().into(),
                );
        }
    }

    if let Some(ssi_jwt::Issuer(iss)) = iss {
        target.insert("issuer".into(), iss.into_string().into());
    }

    if let Some(nbf) = iat.or(nbf) {
        let nbf_date_time: chrono::LocalResult<DateTime<Utc>> = nbf.into();
        if let Some(time) = nbf_date_time.latest() {
            target.insert(
                "issuanceDate".into(),
                xsd_types::DateTime::from(time).to_string().into(),
            );
        }
    }

    if let Some(ssi_jwt::Subject(sub)) = sub {
        let credential_subject = target
            .get_mut_or_insert_with("credentialSubject", || json_syntax::Object::new().into());
        let kind = credential_subject.kind();

        credential_subject
            .as_object_mut()
            .ok_or(JwtVcDecodeError::InvalidCredentialSubject(kind))?
            .insert("id".into(), sub.into_string().into());
    }

    if let Some(ssi_jwt::JwtId(jti)) = jti {
        target.insert("id".into(), jti.into());
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum JwtVpDecodeError {
    #[error("unable to read claim: {0}")]
    Claim(String),

    #[error("missing presentation value")]
    MissingPresentation,

    #[error("unexpected presentation value (found {0}, expected object)")]
    UnexpectedPresentationValue(json_syntax::Kind),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(#[from] json_syntax::DeserializeError),
}

impl JwtVpDecodeError {
    fn claim(e: impl fmt::Display) -> Self {
        Self::Claim(e.to_string())
    }
}

/// Decodes a Verifiable Presentation from a JWT.
///
/// See: <https://www.w3.org/TR/vc-data-model/#json-web-token>
pub fn decode_jwt_vp_claims<T>(mut jwt: impl ClaimSet) -> Result<T, JwtVpDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let ssi_jwt::VerifiablePresentation(vp) = jwt
        .try_remove()
        .map_err(JwtVpDecodeError::claim)?
        .ok_or(JwtVpDecodeError::MissingPresentation)?;

    match vp {
        json_syntax::Value::Object(mut vp) => {
            decode_jwt_vp_specific_headers(jwt, &mut vp)?;
            Ok(json_syntax::from_value(json_syntax::Value::Object(vp))?)
        }
        v => Err(JwtVpDecodeError::UnexpectedPresentationValue(v.kind())),
    }
}

fn decode_jwt_vp_specific_headers(
    mut jwt: impl ClaimSet,
    target: &mut json_syntax::Object,
) -> Result<(), JwtVpDecodeError> {
    let iss = jwt
        .try_remove::<ssi_jwt::Issuer>()
        .map_err(JwtVpDecodeError::claim)?;
    let iat = jwt
        .try_remove::<ssi_jwt::IssuedAt>()
        .map_err(JwtVpDecodeError::claim)?
        .map(|iat| iat.0);
    let nbf = jwt
        .try_remove::<ssi_jwt::NotBefore>()
        .map_err(JwtVpDecodeError::claim)?
        .map(|nbf| nbf.0);
    let jti = jwt
        .try_remove::<ssi_jwt::JwtId>()
        .map_err(JwtVpDecodeError::claim)?;

    if let Some(ssi_jwt::Issuer(iss)) = iss {
        target.insert("holder".into(), iss.into_string().into());
    }

    if let Some(nbf) = iat.or(nbf) {
        let nbf_date_time: chrono::LocalResult<DateTime<Utc>> = nbf.into();
        if let Some(time) = nbf_date_time.latest() {
            target.insert(
                "issuanceDate".into(),
                xsd_types::DateTime::from(time).to_string().into(),
            );
        }
    }

    if let Some(ssi_jwt::JwtId(jti)) = jti {
        target.insert("id".into(), jti.into());
    }

    Ok(())
}
