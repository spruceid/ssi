use chrono::{DateTime, LocalResult, Utc};
use iref::IriBuf;
use json_ld::{JsonLdProcessor, Loader, RemoteDocument, ToRdfError};
use linked_data::{FromLinkedDataError, LinkedDataDeserializeSubject, LinkedDataResource};
use rdf_types::{
    IdInterpretationMut, Interpret, IriVocabulary, LanguageTagVocabulary, TermInterpretationMut,
    VocabularyMut,
};
use ssi_claims_core::Verifiable;
use ssi_jws::{CompactJWSBuf, Header};
use ssi_jwt::{JWTClaims, StringOrURI};
use ssi_vc_core::datatype::VCDateTime;
use std::hash::Hash;

use crate::{verification, Proof, VcJwt};

pub enum Error<E> {
    InvalidType(Option<String>),
    InvalidContentType(Option<String>),
    MissingCredential,
    MissingCredentialSubject,
    CredentialIsNotAnObject,
    InvalidId(String),
    InvalidIssuer,
    InvalidDateTime,
    InvalidSubject,
    Processing(ToRdfError<E>),
    FromRdf(FromLinkedDataError),
    Base64(ssi_jws::Base64DecodeError),
    Json(serde_json::Error),
}

impl<E> From<ssi_jws::InvalidHeader> for Error<E> {
    fn from(value: ssi_jws::InvalidHeader) -> Self {
        match value {
            ssi_jws::InvalidHeader::Base64(e) => Self::Base64(e),
            ssi_jws::InvalidHeader::Json(e) => Self::Json(e),
        }
    }
}

impl<E> From<ssi_jws::Base64DecodeError> for Error<E> {
    fn from(value: ssi_jws::Base64DecodeError) -> Self {
        Self::Base64(value)
    }
}

impl<E> From<serde_json::Error> for Error<E> {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl<E> From<ToRdfError<E>> for Error<E> {
    fn from(value: ToRdfError<E>) -> Self {
        Self::Processing(value)
    }
}

impl<E> From<FromLinkedDataError> for Error<E> {
    fn from(value: FromLinkedDataError) -> Self {
        Self::FromRdf(value)
    }
}

impl<E> From<InvalidId> for Error<E> {
    fn from(value: InvalidId) -> Self {
        Self::InvalidId(value.0)
    }
}

impl<C> VcJwt<C> {
    /// Decode a Linked Data credential encoded as a JSON Web Token.
    pub async fn decode_ld<V, I, L>(
        vocabulary: &mut V,
        interpretation: &mut I,
        loader: &mut L,
        jws: CompactJWSBuf,
    ) -> Result<Verifiable<Self>, Error<L::Error>>
    where
        V: VocabularyMut<
            Type = rdf_types::literal::Type<
                <V as IriVocabulary>::Iri,
                <V as LanguageTagVocabulary>::LanguageTag,
            >,
            Value = String,
        >,
        V::Iri: Clone + Eq + Hash,
        V::BlankId: Clone + Eq + Hash,
        V::Literal: Clone,
        I: TermInterpretationMut<V::Iri, V::BlankId, V::Literal>,
        I::Resource: Eq + Hash + LinkedDataResource<I, V>,
        C: LinkedDataDeserializeSubject<I, V>,
        L: Loader<V::Iri>,
        // required by `json-ld` (for now).
        V: Sync + Send,
        V::Iri: Sync + Send,
        V::BlankId: Sync + Send,
        I::Resource: Sync + Send,
        C: Sync + Send,
        L: Sync + Send,
        L::Error: Send,
    {
        let header = jws.decode_header()?;

        // According to <https://www.w3.org/TR/vc-data-model/#json-web-token>
        // the type, if present, must be set `JWT`.
        // According to <https://w3c.github.io/vc-jwt/> the type must be
        // `vc+ld+jwt`, with `cty` set to `vc+ld+json`.
        match header.type_.as_deref() {
            None | Some("JWT") => match header.content_type.as_deref() {
                None | Some("vc+ld+json") => (),
                Some(_) => return Err(Error::InvalidContentType(header.content_type)),
            },
            Some("vc+ld+jwt") => match header.content_type.as_deref() {
                Some("vc+ld+json") => (),
                _ => return Err(Error::InvalidContentType(header.content_type)),
            },
            Some(_) => return Err(Error::InvalidType(header.type_)),
        }

        let payload = jws.decode_payload(&header)?;
        let mut claims: JWTClaims = serde_json::from_slice(&payload)?;
        let verification_method = build_issuer(&header, &claims)?;

        match claims.verifiable_credential.take() {
            Some(mut credential) => {
                add_claims_to_credential(
                    claims,
                    credential
                        .as_object_mut()
                        .ok_or(Error::CredentialIsNotAnObject)?,
                )?;
                let mut generator = rdf_types::generator::Blank::new();
                let document = RemoteDocument::<V::Iri>::new(None, None, credential);
                let mut to_rdf = document
                    .to_rdf_with(vocabulary, &mut generator, loader)
                    .await?;
                match to_rdf.document().objects().iter().next() {
                    Some(object) => match object.id() {
                        Some(id) => {
                            let id = interpret_id(interpretation, id.clone())?;
                            let dataset: grdf::HashDataset<
                                I::Resource,
                                I::Resource,
                                I::Resource,
                                I::Resource,
                            > = to_rdf
                                .cloned_quads()
                                .map(|quad| quad.interpret(interpretation))
                                .collect();

                            let credential = C::deserialize_subject(
                                vocabulary,
                                interpretation,
                                &dataset,
                                dataset.default_graph(),
                                &id,
                            )?;
                            let proof = Proof::new(jws.decode_signature()?, verification_method);
                            Ok(Verifiable::new(
                                VcJwt::new(credential, header, payload.into_owned()),
                                proof,
                            ))
                        }
                        None => Err(Error::MissingCredentialSubject),
                    },
                    None => Err(Error::MissingCredentialSubject),
                }
            }
            None => Err(Error::MissingCredential),
        }
    }
}

pub struct InvalidId(String);

fn interpret_id<T, B, I: IdInterpretationMut<T, B>>(
    interpretation: &mut I,
    id: json_ld::Id<T, B>,
) -> Result<I::Resource, InvalidId> {
    match id {
        json_ld::Id::Valid(id) => Ok(interpretation.interpret_id(id)),
        json_ld::Id::Invalid(id) => Err(InvalidId(id)),
    }
}

fn build_issuer<E>(header: &Header, claims: &JWTClaims) -> Result<verification::Issuer, Error<E>> {
    let issuer = match &claims.issuer {
        Some(StringOrURI::URI(issuer_uri)) => Some(IriBuf::new(issuer_uri.to_string()).unwrap()),
        Some(StringOrURI::String(_)) => return Err(Error::InvalidIssuer),
        None => None,
    };

    Ok(verification::Issuer::new(issuer, header.key_id.clone()))
}

/// Transform the JWT specific headers and claims according to
/// <https://www.w3.org/TR/vc-data-model/#jwt-decoding>.
fn add_claims_to_credential<E>(
    claims: JWTClaims,
    cred: &mut json_syntax::Object,
) -> Result<(), Error<E>> {
    if let Some(exp) = claims.expiration_time {
        let exp_date_time: LocalResult<DateTime<Utc>> = exp.into();
        let value = exp_date_time
            .latest()
            .map(|time| VCDateTime::new(time.into(), true));

        if let Some(value) = value {
            cred.insert("expirationDate".into(), value.to_string().into());
        }
    }

    if let Some(iss) = claims.issuer {
        match iss {
            StringOrURI::URI(issuer_uri) => {
                match cred
                    .get_unique_mut("issuer")
                    .ok()
                    .flatten()
                    .and_then(json_syntax::Value::as_object_mut)
                {
                    Some(issuer) => {
                        issuer.insert("id".into(), issuer_uri.to_string().into());
                    }
                    None => {
                        cred.insert("issuer".into(), issuer_uri.to_string().into());
                    }
                }
            }
            _ => return Err(Error::InvalidIssuer),
        }
    }

    if let Some(iat) = claims.issuance_date {
        let iat_date_time: LocalResult<DateTime<Utc>> = iat.into();
        let value = iat_date_time
            .latest()
            .map(|time| VCDateTime::new(time.into(), true));

        if let Some(value) = value {
            cred.insert("issuanceDate".into(), value.to_string().into());
        }
    } else if let Some(nbf) = claims.not_before {
        let nbf_date_time: LocalResult<DateTime<Utc>> = nbf.into();
        let value = nbf_date_time
            .latest()
            .map(|time| VCDateTime::new(time.into(), true));

        match value {
            Some(value) => {
                cred.insert("issuanceDate".into(), value.to_string().into());
            }
            None => return Err(Error::InvalidDateTime),
        }
    }

    if let Some(sub) = claims.subject {
        match sub {
            StringOrURI::URI(sub_uri) => {
                match cred
                    .get_unique_mut("credentialSubject")
                    .ok()
                    .flatten()
                    .and_then(json_syntax::Value::as_object_mut)
                {
                    Some(issuer) => {
                        issuer.insert("id".into(), sub_uri.to_string().into());
                    }
                    None => {
                        cred.insert("credentialSubject".into(), sub_uri.to_string().into());
                    }
                }
            }
            StringOrURI::String(_) => {
                return Err(Error::InvalidSubject);
            }
        }
    }

    if let Some(id) = claims.jwt_id {
        cred.insert("id".into(), id.into());
    }

    Ok(())
}
