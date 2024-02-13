use json_ld::{
    compaction::Compact, context_processing::Processed, syntax::IntoJsonWithContext,
    ContextLoadError, ExpandedDocument, Indexed, Loader, Process, RemoteContextReference,
};
use json_syntax::Print;
use linked_data::{AsRdfLiteral, LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    interpretation::{ReverseBlankIdInterpretation, ReverseIriInterpretation},
    Interpretation, ReverseLiteralInterpretation, VocabularyMut,
};
use ssi_claims_core::Verifiable;
use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSigner;
use ssi_vc_core::{vocab::VERIFIABLE_CREDENTIAL, CREDENTIALS_V1_CONTEXT_IRI};
use ssi_verification_methods::{SignatureAlgorithm, SignatureError, Signer, VerificationError};
use std::hash::Hash;

use crate::{verification, Proof, VcJwt};

#[derive(Debug, thiserror::Error)]
pub enum Error<C> {
    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("JSON-LD context loading failed")]
    ContextLoadingFailed(ContextLoadError<C>),

    #[error("JSON-LD context processing failed")]
    ContextProcessingFailed(json_ld::context_processing::Error<C>),

    #[error("JSON-LD compaction failed")]
    CompactionFailed(json_ld::compaction::Error<C>),
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
    pub context: Option<RemoteContextReference<I>>,

    /// Specifies if the <https://www.w3.org/2018/credentials/v1> context is
    /// to be added to the compaction context (true by default).
    pub add_credentials_v1_context: bool,

    /// JSON-LD compaction options.
    pub compaction_options: json_ld::compaction::Options,
}

/// Signature algorithm.
pub struct VcJwtSignatureAlgorithm {
    pub base64_encode: bool,
}

impl Default for VcJwtSignatureAlgorithm {
    fn default() -> Self {
        Self {
            base64_encode: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VcJwtSignature {
    pub header: ssi_jws::Header,
    pub signature_bytes: Vec<u8>,
}

impl Referencable for VcJwtSignature {
    type Reference<'a> = VcJwtSignatureRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        VcJwtSignatureRef {
            header: &self.header,
            signature_bytes: &self.signature_bytes,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy)]
pub struct VcJwtSignatureRef<'a> {
    pub header: &'a ssi_jws::Header,
    pub signature_bytes: &'a [u8],
}

impl SignatureAlgorithm<verification::AnyJwkMethod> for VcJwtSignatureAlgorithm {
    type Options = ();

    type Signature = VcJwtSignature;

    type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

    type Protocol = ();

    async fn sign<S: MessageSigner<ssi_jwk::Algorithm>>(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <verification::AnyJwkMethod as Referencable>::Reference<'_>,
        payload: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        // Prepare JWS header.
        let header = ssi_jws::Header {
            algorithm: method.public_key_jwk.algorithm.unwrap_or_default(),
            type_: Some("vc+ld+jwt".to_string()),
            content_type: Some("vc+ld+json".to_string()),
            base64urlencode_payload: (!self.base64_encode).then_some(false),
            ..Default::default()
        };

        let signing_bytes = header.encode_signing_bytes(payload);

        let signature_bytes = signer.sign(header.algorithm, (), &signing_bytes).await?;

        Ok(VcJwtSignature {
            header,
            signature_bytes,
        })
    }

    fn verify(
        &self,
        _options: (),
        signature: VcJwtSignatureRef,
        method: verification::AnyJwkMethodRef,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let result = ssi_jws::verify_bytes(
            signature.header.algorithm,
            bytes,
            method.public_key_jwk,
            signature.signature_bytes,
        );

        match result {
            Ok(()) => Ok(true),
            Err(ssi_jws::Error::InvalidSignature) => Ok(false),
            Err(ssi_jws::Error::InvalidJWS) => Err(VerificationError::InvalidKey),
            Err(_) => Err(VerificationError::InvalidSignature),
        }
    }
}

impl<C> VcJwt<C> {
    /// Sign the given Linked Data credential.
    pub async fn sign_ld<V, I, L>(
        vocabulary: &mut V,
        interpretation: &mut I,
        loader: &mut L,
        signer: &impl Signer<verification::AnyJwkMethod, ssi_jwk::Algorithm>,
        credential: C,
        signer_info: verification::Issuer,
        options: LdOptions<V::Iri>,
    ) -> Result<Verifiable<Self>, Error<L::Error>>
    where
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash,
        V::BlankId: Clone + Eq + Hash,
        V::LanguageTag: Clone,
        V::Value: AsRdfLiteral<V>,
        I: Interpretation
            + ReverseIriInterpretation<Iri = V::Iri>
            + ReverseBlankIdInterpretation<BlankId = V::BlankId>
            + ReverseLiteralInterpretation<Literal = V::Literal>,
        L: Loader<V::Iri>,
        C: LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
        //
        V: Send + Sync,
        V::Iri: Send + Sync,
        V::BlankId: Send + Sync,
        L: Send + Sync,
        L::Error: Send,
        C: Sync,
    {
        // Produce expanded JSON-LD payload.
        let mut json_ld_vc = Indexed::none(
            json_ld::ser::serialize_object_with(vocabulary, interpretation, &credential).unwrap(),
        );
        if let Some(node) = json_ld_vc.as_node_mut() {
            node.types_mut_or_default()
                .push(json_ld::Id::iri(vocabulary.insert(VERIFIABLE_CREDENTIAL)));
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
                    Some(json_ld::syntax::Context::Many(Vec::new()))
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

                let active_context: Processed<V::Iri, V::BlankId> = context
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
                    .compact_full(
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

        // Build proof.
        let signature = signer
            .sign(
                VcJwtSignatureAlgorithm {
                    base64_encode: options.base64_encode,
                },
                (),
                signer_info.id(),
                signer_info.method_reference(),
                &payload,
            )
            .await?;
        let proof = Proof::new(signature.signature_bytes, signer_info);

        // Build non-verifiable JWT credential.
        let jwt_credential = Self::new(credential, signature.header, payload);

        // Build verifiable JWT credential.
        Ok(Verifiable::new(jwt_credential, proof))
    }
}

fn add_credentials_v1_context(context: &mut json_ld::syntax::Context) {
    fn is_credentials_v1_context(context: &json_ld::syntax::ContextEntry) -> bool {
        match context {
            json_ld::syntax::ContextEntry::IriRef(iri) => {
                iri.as_iri_ref() == CREDENTIALS_V1_CONTEXT_IRI
            }
            _ => false,
        }
    }

    match context {
        json_ld::syntax::Context::One(c) => {
            if !is_credentials_v1_context(c) {
                let c = std::mem::replace(c, json_ld::syntax::ContextEntry::Null);
                *context = json_ld::syntax::Context::Many(vec![
                    c,
                    json_ld::syntax::ContextEntry::IriRef(
                        CREDENTIALS_V1_CONTEXT_IRI.to_owned().into(),
                    ),
                ]);
            }
        }
        json_ld::syntax::Context::Many(list) => {
            if list.is_empty() {
                *context = json_ld::syntax::Context::One(json_ld::syntax::ContextEntry::IriRef(
                    CREDENTIALS_V1_CONTEXT_IRI.to_owned().into(),
                ));
            } else if list.iter().all(|c| !is_credentials_v1_context(c)) {
                list.push(json_ld::syntax::ContextEntry::IriRef(
                    CREDENTIALS_V1_CONTEXT_IRI.to_owned().into(),
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
fn build_vc_claims(mut vc: json_syntax::Value) -> json_syntax::Object {
    let mut claims = json_syntax::Object::new();
    if let Some(vc) = vc.as_object_mut() {
        if let Some(value) = remove_id(vc, "issuer") {
            claims.insert("iss".into(), value.into());
        }

        let issuance_date = claims.remove("issuance_date").next();
        if let Some(entry) = issuance_date {
            claims.insert("iat".into(), entry.value);
        }

        let expiration_date = claims.remove("expiration_date").next();
        if let Some(entry) = expiration_date {
            claims.insert("exp".into(), entry.value);
        }

        if let Some(value) = remove_id(vc, "credential_subject") {
            claims.insert("sub".into(), value.into());
        }

        let id = claims.remove("id").next();
        if let Some(entry) = id {
            claims.insert("jti".into(), entry.value);
        }
    }
    claims.insert("vc".into(), vc);
    claims
}

fn remove_id(object: &mut json_syntax::Object, key: &str) -> Option<String> {
    match object.get_mut(key).next() {
        Some(value) => match value {
            json_syntax::Value::String(_) => {
                let entry: json_syntax::object::Entry = object.remove(key).next().unwrap();
                Some(entry.into_value().into_string().unwrap().into_string())
            }
            json_syntax::Value::Object(o) => {
                let id_entry = o.remove("id").next();
                match id_entry {
                    Some(entry) => match entry.value {
                        json_syntax::Value::String(id) => Some(id.into_string()),
                        other => {
                            o.insert("id".into(), other);
                            None
                        }
                    },
                    None => None,
                }
            }
            _ => None,
        },
        None => None,
    }
}
