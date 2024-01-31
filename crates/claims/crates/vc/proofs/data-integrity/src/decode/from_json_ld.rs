use iref::IriBuf;
use json_ld::{ContextLoader, Loader, RemoteDocumentReference};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use locspan::{Meta, Stripped};
use rdf_types::{Interpretation, Vocabulary, VocabularyMut};
use std::hash::Hash;

use super::{DataIntegrityInput, DecodeError, PROOF_IRI};

/// JSON-LD Data-Integrity input.
///
/// This is a simple wrapper around [`RemoteDocumentReference<I>`] that adds
/// the ability to expand and extract a Data-Integrity proof from the wrapped
/// (remote) JSON-LD document.
pub struct JsonLdInput<'l, I = IriBuf, L = ssi_json_ld::ContextLoader> {
    document: RemoteDocumentReference<I>,
    loader: &'l mut L,
}

impl<'l, I, L> JsonLdInput<'l, I, L> {
    pub fn new(loader: &'l mut L, document: RemoteDocumentReference<I>) -> Self {
        Self { loader, document }
    }
}

impl<'l, I: Interpretation, V: Vocabulary, L> DataIntegrityInput<I, V>
    for JsonLdInput<'l, V::Iri, L>
where
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    L: Loader<V::Iri> + ContextLoader<V::Iri>,
    L::Output: Into<json_ld::syntax::Value>,
    // Required by `json-ld` for now
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
    L::ContextError: Send,
{
    type Error = json_ld::ExpandError<(), L::Error, L::ContextError>;

    type Data = json_ld::Document<V::Iri, V::BlankId>;

    type Proof = json_ld::Node<V::Iri, V::BlankId>;

    async fn extract_proof<'a>(
        self,
        vocabulary: &'a mut V,
        _interpretation: &'a mut I,
    ) -> Result<(Self::Data, Self::Proof), DecodeError<Self::Error>>
    where
        Self: 'a,
    {
        let options = json_ld::Options {
            expansion_policy: json_ld::expansion::Policy::Strictest,
            ..Default::default()
        };

        extract_json_ld_proof(vocabulary, self.loader, self.document, options).await
    }
}

pub(crate) async fn extract_json_ld_proof<'a, I: Interpretation, V: Vocabulary, L>(
    vocabulary: &'a mut V,
    loader: &'a mut L,
    document: RemoteDocumentReference<V::Iri>,
    options: json_ld::Options<V::Iri, ()>,
) -> Result<
    (
        json_ld::Document<V::Iri, V::BlankId>,
        json_ld::Node<V::Iri, V::BlankId>,
    ),
    DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>,
>
where
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    L: Loader<V::Iri> + ContextLoader<V::Iri>,
    L::Output: Into<json_ld::syntax::Value>,
    // Required by `json-ld` for now
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
    L::ContextError: Send,
{
    use json_ld::JsonLdProcessor;
    let (mut remote, Meta(expanded, meta)) = document
        .into_document_with_using(vocabulary, loader, options)
        .await
        .map_err(DecodeError::Input)?
        .into_parts();

    // Remove the `proof` term from the JSON representation.
    match remote.document_mut().0.as_object_mut() {
        Some(object) => {
            let mut proofs = object.remove("proof");
            if proofs.next().is_none() {
                todo!() // missing proof
            }
        }
        None => {
            todo!() // not an object
        }
    }

    match expanded.into_main_node() {
        Some(mut node) => match vocabulary.get(PROOF_IRI).map(json_ld::Id::iri) {
            Some(proof_iri) => {
                match node
                    .properties_mut()
                    .remove(&proof_iri)
                    .and_then(|objects| objects.value.into_iter().next())
                {
                    Some(Stripped(Meta(proof_object, _))) => match proof_object.into_inner() {
                        json_ld::Object::Node(proof_node) => {
                            let document = json_ld::Document::new(
                                remote,
                                Meta(node.map(json_ld::Indexed::none).into(), meta),
                            );

                            use contextual::WithContext;
                            use json_ld::syntax::Print;
                            eprintln!(
                                "proof node: {}",
                                (*proof_node).with(&*vocabulary).pretty_print()
                            );

                            Ok((document, *proof_node))
                        }
                        _ => {
                            todo!()
                        }
                    },
                    None => {
                        todo!()
                    }
                }
            }
            None => {
                todo!()
            }
        },
        None => Err(DecodeError::MissingSubject),
    }
}
