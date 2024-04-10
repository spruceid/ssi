use chrono::{DateTime, Utc};
use ssi_jwt::{JWTClaims, RegisteredClaim, RegisteredClaimKind};

#[derive(Debug, thiserror::Error)]
pub enum JwtVcDecodeError {
    #[error("missing credential value")]
    MissingCredential,

    #[error("unexpected credential value (found {0}, expected object)")]
    UnexpectedCredentialValue(json_syntax::Kind),

    #[error("invalid credential subject: expected object, found {0}")]
    InvalidCredentialSubject(json_syntax::Kind),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(#[from] json_syntax::DeserializeError),
}

/// Decodes a Verifiable Credential form a JWT.
///
/// See: <https://www.w3.org/TR/vc-data-model/#json-web-token>
pub fn decode_jwt_vc_claims<T>(mut jwt: JWTClaims) -> Result<T, JwtVcDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    match jwt.registered_claims.remove(RegisteredClaimKind::VerifiableCredential) {
        Some(RegisteredClaim::VerifiableCredential(vc)) => match vc {
            json_syntax::Value::Object(mut vc) => {
                decode_jwt_vc_specific_headers(jwt, &mut vc)?;
                Ok(json_syntax::from_value(json_syntax::Value::Object(vc))?)
            }
            v => Err(JwtVcDecodeError::UnexpectedCredentialValue(v.kind())),
        }
        Some(_) => panic!(), // unsound claim set.
        None => Err(JwtVcDecodeError::MissingCredential),
    }
}

fn decode_jwt_vc_specific_headers(
    jwt: JWTClaims,
    target: &mut json_syntax::Object,
) -> Result<(), JwtVcDecodeError> {
    if let Some(exp) = jwt.expiration_time {
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

    if let Some(iss) = jwt.issuer {
        target.insert("issuer".into(), iss.into_string().into());
    }

    if let Some(nbf) = jwt.issuance_date.or(jwt.not_before) {
        let nbf_date_time: chrono::LocalResult<DateTime<Utc>> = nbf.into();
        if let Some(time) = nbf_date_time.latest() {
            target.insert(
                "issuanceDate".into(),
                xsd_types::DateTime::from(time).to_string().into(),
            );
        }
    }

    if let Some(sub) = jwt.subject {
        let credential_subject = target
            .get_mut_or_insert_with("credentialSubject", || json_syntax::Object::new().into());
        let kind = credential_subject.kind();

        credential_subject
            .as_object_mut()
            .ok_or(JwtVcDecodeError::InvalidCredentialSubject(kind))?
            .insert("id".into(), sub.into_string().into());
    }

    if let Some(jti) = jwt.jwt_id {
        target.insert("id".into(), jti.into());
    }

    Ok(())
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

/// Decodes a Verifiable Presentation from a JWT.
///
/// See: <https://www.w3.org/TR/vc-data-model/#json-web-token>
pub fn decode_jwt_vp_claims<T>(mut jwt: JWTClaims) -> Result<T, JwtVpDecodeError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    match jwt.registered_claims.remove(RegisteredClaimKind::VerifiableCredential) {
        Some(RegisteredClaim::VerifiablePresentation(vp)) => match vp {
            json_syntax::Value::Object(mut vp) => {
                decode_jwt_vp_specific_headers(jwt, &mut vp);
                Ok(json_syntax::from_value(json_syntax::Value::Object(vp))?)
            }
            v => Err(JwtVpDecodeError::UnexpectedPresentationValue(v.kind())),
        }
        Some(_) => panic!(), // unsound claim set.
        None => Err(JwtVpDecodeError::MissingPresentation),
    }
}

fn decode_jwt_vp_specific_headers(
    jwt: JWTClaims,
    target: &mut json_syntax::Object,
) {
    if let Some(iss) = jwt.issuer {
        target.insert("holder".into(), iss.into_string().into());
    }

    if let Some(nbf) = jwt.issuance_date.or(jwt.not_before) {
        let nbf_date_time: chrono::LocalResult<DateTime<Utc>> = nbf.into();
        if let Some(time) = nbf_date_time.latest() {
            target.insert(
                "issuanceDate".into(),
                xsd_types::DateTime::from(time).to_string().into(),
            );
        }
    }

    if let Some(jti) = jwt.jwt_id {
        target.insert("id".into(), jti.into());
    }
}
