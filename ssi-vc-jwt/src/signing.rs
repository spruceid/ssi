use std::hash::Hash;

use json_ld::{
    compaction::CompactMeta, context_processing::Processed, syntax::IntoJsonWithContext,
    ContextLoader, ExpandedDocument, Loader, Process, RemoteDocumentReference,
};
use json_syntax::Print;
use locspan::Meta;
use rdf_types::VocabularyMut;
use ssi_vc::{vocab::VERIFIABLE_CREDENTIAL, Verifiable, CREDENTIALS_V1_CONTEXT_IRI};
use ssi_verification_methods::{SignatureError, SignatureAlgorithm, Signer};

use crate::{verification, Proof, VcJwt};

#[derive(Debug, thiserror::Error)]
pub enum Error<C> {
    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("JSON-LD context loading failed")]
    ContextLoadingFailed(C),

    #[error("JSON-LD context processing failed")]
    ContextProcessingFailed(json_ld::context_processing::MetaError<(), C>),

    #[error("JSON-LD compaction failed")]
    CompactionFailed(json_ld::compaction::MetaError<(), C>),
}

/// JWT+LD signature options.
pub struct LdOptions<I> {
    /// Use base64 to encode the payload (true by default).
    pub base64_encode: bool,

    /// JSON-LD context processing options.
    pub context_processing_options: json_ld::context_processing::Options,

    /// Compaction context.
    ///
    /// This context is used to compact the JSON-LD payload and will appear
    /// in the credential. If the `add_credentials_v1_context` is set to `true`
    /// (by default) then the <https://www.w3.org/2018/credentials/v1> will be
    /// added to the context, even if `None` is passed.
    pub context: Option<RemoteDocumentReference<I, (), json_ld::syntax::context::Value<()>>>,

    /// Specifies if the <https://www.w3.org/2018/credentials/v1> context is
    /// to be added to the compaction context (true by default).
    pub add_credentials_v1_context: bool,

    /// JSON-LD compaction options.
    pub compaction_options: json_ld::compaction::Options,
}

/// Signature algorithm.
pub struct VcJwtSignature;

impl SignatureAlgorithm<verification::Method> for VcJwtSignature {
    type Signature = Vec<u8>;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
        &self,
        method: &verification::Method,
        bytes: &[u8],
        signer: &S
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(&self,
        signature: &Self::Signature,
        method: &verification::Method,
        bytes: &[u8]
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}

impl<C: Sync> VcJwt<C> {
    /// Sign the given Linked Data credential.
    pub async fn sign_ld<V, I, L>(
        vocabulary: &mut V,
        interpretation: &I,
        loader: &mut L,
        signer: &impl Signer<verification::Method, ()>,
        credential: C,
        method: verification::Method,
        options: LdOptions<V::Iri>,
    ) -> Result<Verifiable<Self>, Error<L::ContextError>>
    where
        V: VocabularyMut + Send + Sync,
        V::Iri: Clone + Eq + Hash + Send + Sync,
        V::BlankId: Clone + Eq + Hash + Send + Sync,
        L: Loader<V::Iri, ()> + ContextLoader<V::Iri, ()> + Send + Sync,
        L::Context: Into<json_ld::syntax::context::Value<()>>,
        C: treeldr_rust_prelude::AsJsonLdObjectMeta<V, I>,
    {
        // Prepare JWS header.
        let header = ssi_jws::Header {
            type_: Some("vc+ld+jwt".to_string()),
            content_type: Some("vc+ld+json".to_string()),
            base64urlencode_payload: (!options.base64_encode).then_some(false),
            ..Default::default()
        };

        // Produce expanded JSON-LD payload.
        let mut json_ld_vc = credential.as_json_ld_object_meta(vocabulary, interpretation, ());
        if let Some(node) = json_ld_vc.as_node_mut() {
            node.type_entry_or_default((), ()).push(Meta(
                json_ld::Id::iri(vocabulary.insert(VERIFIABLE_CREDENTIAL)),
                (),
            ));
        }

        // Prepare compaction context.
        let context = match options.context {
            Some(context) => Some(
                context
                    .load_context_with(vocabulary, loader)
                    .await
                    .map_err(Error::ContextLoadingFailed)?
                    .into_document(),
            ),
            None => {
                if options.add_credentials_v1_context {
                    Some(Meta(json_ld::syntax::context::Value::Many(Vec::new()), ()))
                } else {
                    None
                }
            }
        };

        // Compact JSON-LD payload (if necessary).
        let json_vc = match context {
            Some(mut context) => {
                if options.add_credentials_v1_context {
                    add_credentials_v1_context(&mut context);
                }

                let active_context: Processed<V::Iri, V::BlankId, _, ()> = context
                    .process_full(
                        vocabulary,
                        &json_ld::Context::new(None),
                        loader,
                        None,
                        options.context_processing_options,
                        json_ld::warning::PrintWith,
                    )
                    .await
                    .map_err(Error::ContextProcessingFailed)?;

                let mut json_ld_vc_doc = ExpandedDocument::new();
                json_ld_vc_doc.insert(json_ld_vc);
                json_ld_vc_doc
                    .compact_full_meta(
                        &(),
                        vocabulary,
                        active_context.as_ref(),
                        loader,
                        options.compaction_options,
                    )
                    .await
                    .map_err(Error::CompactionFailed)?
            }
            None => json_ld_vc.into_json_with(vocabulary),
        };

        // Build signing bytes.
        let claims = build_vc_claims(json_vc);
        let payload = json_syntax::Value::Object(claims)
            .compact_print()
            .to_string()
            .into_bytes();
        let signing_bytes = header.encode_signing_bytes(&payload);

        // Build proof.
        let signature = signer.sign(VcJwtSignature,&method, &signing_bytes)?;
        let proof = Proof::new(signature, method);

        // Build non-verifiable JWT credential.
        let jwt_credential = unsafe { Self::new_unchecked(credential, signing_bytes) };

        // Build verifiable JWT credential.
        Ok(Verifiable::new(jwt_credential, proof))
    }
}

fn add_credentials_v1_context(context: &mut json_ld::syntax::context::Value<()>) {
    fn is_credentials_v1_context<D>(context: &json_ld::syntax::Context<D>) -> bool {
        match context {
            json_ld::syntax::Context::IriRef(iri) => iri.as_iri_ref() == CREDENTIALS_V1_CONTEXT_IRI,
            _ => false,
        }
    }

    match context {
        json_ld::syntax::context::Value::One(Meta(c, _)) => {
            if !is_credentials_v1_context(c) {
                let c = std::mem::replace(c, json_ld::syntax::Context::Null);
                *context = json_ld::syntax::context::Value::Many(vec![
                    Meta(c, ()),
                    Meta(
                        json_ld::syntax::Context::IriRef(CREDENTIALS_V1_CONTEXT_IRI.into()),
                        (),
                    ),
                ]);
            }
        }
        json_ld::syntax::context::Value::Many(list) => {
            if list.is_empty() {
                *context = json_ld::syntax::context::Value::One(Meta(
                    json_ld::syntax::Context::IriRef(CREDENTIALS_V1_CONTEXT_IRI.into()),
                    (),
                ));
            } else if list.iter().all(|Meta(c, _)| !is_credentials_v1_context(c)) {
                list.push(Meta(
                    json_ld::syntax::Context::IriRef(CREDENTIALS_V1_CONTEXT_IRI.into()),
                    (),
                ))
            }
        }
    }
}

/// Build JWT VC claims from the `vc` claim.
///
/// Some parts of the VC properties are standard JWT claims. This function moves
/// them to the toplevel JWT claims, which is then returned. They will be
/// moved back inside the `vc` claim upon decoding.
fn build_vc_claims(mut vc: Meta<json_syntax::Value, ()>) -> json_syntax::Object {
    let mut claims = json_syntax::Object::new();
    if let Some(vc) = vc.as_object_mut() {
        if let Some(value) = remove_id(vc, "issuer") {
            claims.insert(Meta("iss".into(), ()), Meta(value.into(), ()));
        }

        let issuance_date = claims.remove("issuance_date").next();
        if let Some(entry) = issuance_date {
            claims.insert(Meta("iat".into(), ()), entry.value);
        }

        let expiration_date = claims.remove("expiration_date").next();
        if let Some(entry) = expiration_date {
            claims.insert(Meta("exp".into(), ()), entry.value);
        }

        if let Some(value) = remove_id(vc, "credential_subject") {
            claims.insert(Meta("sub".into(), ()), Meta(value.into(), ()));
        }

        let id = claims.remove("id").next();
        if let Some(entry) = id {
            claims.insert(Meta("jti".into(), ()), entry.value);
        }
    }
    claims.insert(Meta("vc".into(), ()), vc);
    claims
}

fn remove_id(object: &mut json_syntax::Object<()>, key: &str) -> Option<String> {
    match object.get_mut(key).next() {
        Some(Meta(value, ())) => match value {
            json_syntax::Value::String(_) => {
                let entry: json_syntax::object::Entry = object.remove(key).next().unwrap();
                Some(
                    entry
                        .into_value()
                        .into_value()
                        .into_string()
                        .unwrap()
                        .into_string(),
                )
            }
            json_syntax::Value::Object(o) => {
                let id_entry = o.remove("id").next();
                match id_entry {
                    Some(entry) => {
                        let Meta(value, ()) = entry.value;
                        match value {
                            json_syntax::Value::String(id) => Some(id.into_string()),
                            other => {
                                o.insert(Meta("id".into(), ()), Meta(other, ()));
                                None
                            }
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        },
        None => None,
    }
}
