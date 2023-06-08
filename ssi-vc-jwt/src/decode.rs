use async_trait::async_trait;
use chrono::{DateTime, LocalResult, Utc};
use json_ld::{
    context_processing::ProcessMeta, ContextLoader, JsonLdProcessor, Loader, RemoteDocument,
    ToRdfError,
};
use locspan::Meta;
use rdf_types::{FromBlankId, FromIri, Namespace, VocabularyMut};
use ssi_jws::{CompactJWSBuf, Header};
use ssi_jwt::{JWTClaims, StringOrURI};
use ssi_vc::{datatype::VCDateTime, Verifiable};
use std::{hash::Hash, marker::PhantomData};
use treeldr_rust_prelude::{iref::IriBuf, FromRdf, FromRdfError};

use crate::{verification, Encoded, Proof};

pub struct Decoder<C, L> {
    loader: L,
    c: PhantomData<C>,
}

pub enum Error<L, C> {
    MissingCredential,
    MissingCredentialSubject,
    CredentialIsNotAnObject,
    InvalidId(String),
    InvalidIssuer,
    InvalidDateTime,
    InvalidSubject,
    Processing(ToRdfError<(), L, C>),
    FromRdf(FromRdfError),
}

impl<L, C> From<ToRdfError<(), L, C>> for Error<L, C> {
    fn from(value: ToRdfError<(), L, C>) -> Self {
        Self::Processing(value)
    }
}

impl<L, C> From<FromRdfError> for Error<L, C> {
    fn from(value: FromRdfError) -> Self {
        Self::FromRdf(value)
    }
}

impl<L, C> From<InvalidId> for Error<L, C> {
    fn from(value: InvalidId) -> Self {
        Self::InvalidId(value.0)
    }
}

#[async_trait]
impl<N, C, L> ssi_vc::Decoder<N, CompactJWSBuf> for Decoder<C, L>
where
    N: Namespace + VocabularyMut + Sync + Send,
    N::Id: Eq + Hash + FromIri<Iri = N::Iri> + FromBlankId<BlankId = N::BlankId>,
    N::Iri: Clone + Eq + Hash + Sync + Send,
    N::BlankId: Clone + Eq + Hash + Sync + Send,
    C: FromRdf<N, rdf_types::Literal<String, N::Iri>> + Send,
    L: Loader<N::Iri, ()> + ContextLoader<N::Iri, ()> + Sync + Send,
    L::Output: Into<json_syntax::Value>,
    L::Context: ProcessMeta<N::Iri, N::BlankId, ()> + Into<json_ld::syntax::context::Value<()>>,
    L::Error: Send,
    L::ContextError: Send,
{
    type Credential = Encoded<C>;
    type Proof = Proof;

    type Error = Error<L::Error, L::ContextError>;

    async fn decode(
        &mut self,
        namespace: &mut N,
        jws: CompactJWSBuf,
    ) -> Result<ssi_vc::Verifiable<Self::Credential, Self::Proof>, Self::Error> {
        let header = jws.decode_header().unwrap(); // TODO error.
        let mut claims: JWTClaims =
            serde_json::from_slice(&jws.decode_payload(&header).unwrap()).unwrap(); // TODO errors.
        let verification_method = build_verification_method(&header, &claims)?;

        match claims.verifiable_credential.take() {
            Some(mut credential) => {
                add_claims_to_credential(
                    claims,
                    credential
                        .as_object_mut()
                        .ok_or(Error::CredentialIsNotAnObject)?,
                )?;
                let mut generator = rdf_types::generator::Blank::new().with_default_metadata();
                let document = RemoteDocument::<N::Iri, (), json_syntax::Value>::new(
                    None,
                    None,
                    Meta(credential, ()),
                );
                let mut to_rdf = document
                    .to_rdf_with(namespace, &mut generator, &mut self.loader)
                    .await?;
                match to_rdf.document().objects().iter().next() {
                    Some(object) => {
                        match object.id() {
                            Some(Meta(id, _)) => {
                                let id: N::Id = import_id(id.clone())?;
                                let dataset: treeldr_rust_prelude::grdf::HashDataset<
                                    N::Id,
                                    N::Id,
                                    rdf_types::Object<N::Id, rdf_types::Literal<String, N::Iri>>,
                                    N::Id,
                                > = to_rdf.cloned_quads().map(import_valid_quad).collect();

                                let subject = rdf_types::Object::Id(id);
                                let credential =
                                    C::from_rdf(namespace, &subject, dataset.default_graph())?;
                                let proof = Proof::new(
                                    header.algorithm,
                                    jws.decode_signature().unwrap(), // TODO error.
                                    verification_method,
                                );
                                Ok(Verifiable::new(
                                    Encoded::new(credential, jws.into_signing_bytes()),
                                    proof,
                                ))
                            }
                            None => Err(Error::MissingCredentialSubject),
                        }
                    }
                    None => Err(Error::MissingCredentialSubject),
                }
            }
            None => Err(Error::MissingCredential),
        }
    }
}

pub struct InvalidId(String);

fn import_id<T>(id: json_ld::Id<T::Iri, T::BlankId>) -> Result<T, InvalidId>
where
    T: FromIri,
    T: FromBlankId,
{
    match id {
        json_ld::Id::Valid(json_ld::ValidId::Iri(i)) => Ok(FromIri::from_iri(i)),
        json_ld::Id::Valid(json_ld::ValidId::Blank(b)) => Ok(FromBlankId::from_blank(b)),
        json_ld::Id::Invalid(id) => Err(InvalidId(id.clone())),
    }
}

fn import_valid_id<T>(id: json_ld::ValidId<T::Iri, T::BlankId>) -> T
where
    T: FromIri,
    T: FromBlankId,
{
    match id {
        json_ld::ValidId::Iri(i) => FromIri::from_iri(i),
        json_ld::ValidId::Blank(b) => FromBlankId::from_blank(b),
    }
}

fn import_valid_term<T, L>(
    value: rdf_types::Term<json_ld::ValidId<T::Iri, T::BlankId>, L>,
) -> rdf_types::Term<T, L>
where
    T: FromIri,
    T: FromBlankId,
{
    match value {
        rdf_types::Term::Id(id) => rdf_types::Term::Id(import_valid_id(id)),
        rdf_types::Term::Literal(l) => rdf_types::Term::Literal(l),
    }
}

fn import_valid_quad<T, L>(
    rdf_types::Quad(s, p, o, g): rdf_types::Quad<
        json_ld::ValidId<T::Iri, T::BlankId>,
        json_ld::ValidId<T::Iri, T::BlankId>,
        rdf_types::Term<json_ld::ValidId<T::Iri, T::BlankId>, L>,
        json_ld::ValidId<T::Iri, T::BlankId>,
    >,
) -> rdf_types::Quad<T, T, rdf_types::Term<T, L>, T>
where
    T: FromIri,
    T: FromBlankId,
{
    rdf_types::Quad(
        import_valid_id(s),
        import_valid_id(p),
        import_valid_term(o),
        g.map(import_valid_id),
    )
}

fn build_verification_method<L, C>(
    header: &Header,
    claims: &JWTClaims,
) -> Result<verification::Method, Error<L, C>> {
    let issuer = match &claims.issuer {
        Some(StringOrURI::URI(issuer_uri)) => Some(IriBuf::new(issuer_uri.as_str()).unwrap()),
        Some(StringOrURI::String(_)) => return Err(Error::InvalidIssuer),
        None => None,
    };

    Ok(verification::Method::new(issuer, header.key_id.clone()))
}

/// Transform the JWT specific headers and claims according to
/// <https://www.w3.org/TR/vc-data-model/#jwt-decoding>.
fn add_claims_to_credential<L, C>(
    claims: JWTClaims,
    cred: &mut json_syntax::Object,
) -> Result<(), Error<L, C>> {
    if let Some(exp) = claims.expiration_time {
        let exp_date_time: LocalResult<DateTime<Utc>> = exp.into();
        let value = exp_date_time
            .latest()
            .map(|time| VCDateTime::new(time.into(), true));

        if let Some(value) = value {
            cred.insert(
                Meta("expiration_date".into(), ()),
                Meta(String::from(value).into(), ()),
            );
        }
    }

    if let Some(iss) = claims.issuer {
        match iss {
            StringOrURI::URI(issuer_uri) => {
                match cred
                    .get_unique_mut("issuer")
                    .ok()
                    .flatten()
                    .map(Meta::value_mut)
                    .map(json_syntax::Value::as_object_mut)
                    .flatten()
                {
                    Some(issuer) => {
                        issuer.insert(
                            Meta("id".into(), ()),
                            Meta(issuer_uri.to_string().into(), ()),
                        );
                    }
                    None => {
                        cred.insert(
                            Meta("issuer".into(), ()),
                            Meta(issuer_uri.to_string().into(), ()),
                        );
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
            cred.insert(
                Meta("issuance_date".into(), ()),
                Meta(String::from(value).into(), ()),
            );
        }
    } else if let Some(nbf) = claims.not_before {
        let nbf_date_time: LocalResult<DateTime<Utc>> = nbf.into();
        let value = nbf_date_time
            .latest()
            .map(|time| VCDateTime::new(time.into(), true));

        match value {
            Some(value) => {
                cred.insert(
                    Meta("issuance_date".into(), ()),
                    Meta(String::from(value).into(), ()),
                );
            }
            None => return Err(Error::InvalidDateTime),
        }
    }

    if let Some(sub) = claims.subject {
        match sub {
            StringOrURI::URI(sub_uri) => {
                match cred
                    .get_unique_mut("credential_subject")
                    .ok()
                    .flatten()
                    .map(Meta::value_mut)
                    .map(json_syntax::Value::as_object_mut)
                    .flatten()
                {
                    Some(issuer) => {
                        issuer.insert(Meta("id".into(), ()), Meta(sub_uri.to_string().into(), ()));
                    }
                    None => {
                        cred.insert(
                            Meta("credential_subject".into(), ()),
                            Meta(sub_uri.to_string().into(), ()),
                        );
                    }
                }
            }
            StringOrURI::String(_) => {
                return Err(Error::InvalidSubject);
            }
        }
    }

    if let Some(id) = claims.jwt_id {
        cred.insert(Meta("id".into(), ()), Meta(id.into(), ()));
    }

    Ok(())
}
