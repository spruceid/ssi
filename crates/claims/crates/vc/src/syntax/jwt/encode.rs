use serde::Serialize;
use ssi_jwt::RegisteredClaims;

#[derive(Debug, thiserror::Error)]
pub enum JwtVcEncodeError {
    #[error(transparent)]
    Serialization(#[from] json_syntax::SerializeError),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("invalid date value")]
    InvalidDateValue,

    #[error(transparent)]
    NumericDateConversion(#[from] ssi_jwt::NumericDateConversionError),

    #[error("invalid issuer value")]
    InvalidIssuerValue,

    #[error("invalid subject value")]
    InvalidSubjectValue,

    #[error("invalid id value")]
    InvalidIdValue,

    #[error(transparent)]
    InvalidUri(#[from] iref::InvalidUri<String>),
}

pub fn encode_jwt_vc_claims<T: Serialize>(
    credential: &T,
) -> Result<RegisteredClaims, JwtVcEncodeError> {
    let mut credential = json_syntax::to_value(credential)?
        .into_object()
        .ok_or(JwtVcEncodeError::ExpectedJsonObject)?;
    let mut claims = RegisteredClaims::default();

    if let Some(date_value) =
        take_object_property(&mut credential, "credentialSubject", "expirationDate")
    {
        match date_value.into_string() {
            Some(date_value) => {
                let date_value: xsd_types::DateTime = date_value
                    .parse()
                    .map_err(|_| JwtVcEncodeError::InvalidDateValue)?;
                claims.set(ssi_jwt::ExpirationTime(date_value.earliest().try_into()?));
            }
            None => return Err(JwtVcEncodeError::InvalidDateValue),
        }
    }

    if let Some(issuer_entry) = credential.remove("issuer").next() {
        match issuer_entry.value.into_string() {
            Some(issuer_value) => {
                claims.set(ssi_jwt::Issuer(issuer_value.into_string().try_into()?));
            }
            None => return Err(JwtVcEncodeError::InvalidIssuerValue),
        }
    }

    if let Some(issuance_date_entry) = credential.remove("issuanceDate").next() {
        match issuance_date_entry.value.into_string() {
            Some(issuance_date_value) => {
                let issuance_date_value: xsd_types::DateTime = issuance_date_value
                    .parse()
                    .map_err(|_| JwtVcEncodeError::InvalidDateValue)?;
                claims.set(ssi_jwt::NotBefore(issuance_date_value.latest().try_into()?));
            }
            None => return Err(JwtVcEncodeError::InvalidDateValue),
        }
    }

    if let Some(subject_value) =
        take_value_or_object_property(&mut credential, "credentialSubject", "id")
    {
        match subject_value.into_string() {
            Some(subject_value) => {
                claims.set(ssi_jwt::Subject(subject_value.into_string().try_into()?));
            }
            None => return Err(JwtVcEncodeError::InvalidSubjectValue),
        }
    }

    if let Some(id_entry) = credential.remove("id").next() {
        match id_entry.value.into_string() {
            Some(id_value) => {
                claims.set(ssi_jwt::JwtId(id_value.into_string()));
            }
            None => return Err(JwtVcEncodeError::InvalidIdValue),
        }
    }

    claims.set(ssi_jwt::VerifiableCredential(json_syntax::Value::Object(
        credential,
    )));

    Ok(claims)
}

#[derive(Debug, thiserror::Error)]
pub enum JwtVpEncodeError {
    #[error(transparent)]
    Serialization(#[from] json_syntax::SerializeError),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("invalid date value")]
    InvalidDateValue,

    #[error(transparent)]
    NumericDateConversion(#[from] ssi_jwt::NumericDateConversionError),

    #[error("invalid holder value")]
    InvalidHolderValue,

    #[error("invalid id value")]
    InvalidIdValue,

    #[error(transparent)]
    InvalidUri(#[from] iref::InvalidUri<String>),
}

pub fn encode_jwt_vp_claims<T: Serialize>(
    presentation: &T,
) -> Result<RegisteredClaims, JwtVpEncodeError> {
    let mut vp = json_syntax::to_value(presentation)?
        .into_object()
        .ok_or(JwtVpEncodeError::ExpectedJsonObject)?;
    let mut claims = RegisteredClaims::default();

    if let Some(holder_entry) = vp.remove("holder").next() {
        match holder_entry.value.into_string() {
            Some(holder_value) => {
                claims.set(ssi_jwt::Issuer(holder_value.into_string().try_into()?));
            }
            None => return Err(JwtVpEncodeError::InvalidHolderValue),
        }
    }

    if let Some(issuance_date_entry) = vp.remove("issuanceDate").next() {
        match issuance_date_entry.value.into_string() {
            Some(issuance_date_value) => {
                let issuance_date_value: xsd_types::DateTime = issuance_date_value
                    .parse()
                    .map_err(|_| JwtVpEncodeError::InvalidDateValue)?;
                claims.set(ssi_jwt::NotBefore(issuance_date_value.latest().try_into()?));
            }
            None => return Err(JwtVpEncodeError::InvalidDateValue),
        }
    }

    if let Some(id_entry) = vp.remove("id").next() {
        match id_entry.value.into_string() {
            Some(id_value) => {
                claims.set(ssi_jwt::JwtId(id_value.into_string()));
            }
            None => return Err(JwtVpEncodeError::InvalidIdValue),
        }
    }

    claims.set(ssi_jwt::VerifiablePresentation(json_syntax::Value::Object(
        vp,
    )));

    Ok(claims)
}

fn take_object_property(
    source: &mut json_syntax::Object,
    object: &str,
    prop: &str,
) -> Option<json_syntax::Value> {
    source
        .get_mut(object)
        .next()?
        .as_object_mut()?
        .remove(prop)
        .next()
        .map(json_syntax::object::Entry::into_value)
}

fn take_value_or_object_property(
    source: &mut json_syntax::Object,
    object: &str,
    prop: &str,
) -> Option<json_syntax::Value> {
    let v = source.get_mut(object).next()?;

    match v {
        json_syntax::Value::Object(o) => o
            .remove(prop)
            .next()
            .map(json_syntax::object::Entry::into_value),
        _ => source
            .remove(object)
            .next()
            .map(json_syntax::object::Entry::into_value),
    }
}
