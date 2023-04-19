use std::marker::PhantomData;

use rdf_types::{Generator, Namespace, Object, Quad, TryExportQuad};
use treeldr_rust_prelude::RdfIterator;

pub mod suite;

/// Linked Data capable credential.
pub trait LinkedDataCredential {
    type Context;

    /// Iterator over the RDF quads defined by the credential.
    type Quads<'a>: Iterator<Item = Quad>
    where
        Self: 'a,
        Self::Context: 'a;

    /// Returns an iterator over the RDF quads defined by the credential.
    fn quads<'a>(&'a self, context: &'a mut Self::Context) -> Self::Quads<'a>;

    /// Puts the RDF graph in canonical form using URDNA2015.
    fn canonical_form(&self, context: &mut Self::Context) -> Vec<Quad> {
        let quads: Vec<_> = self.quads(context).collect();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

pub struct InNamespace<'t, 'n, T, N, L, C, G> {
    value: &'t T,
    d: PhantomData<&'n (N, L, C, G)>,
}

pub struct LinkedDataCredentialContext<'n, N, L, C, G> {
    namespace: &'n mut N,
    generator: G,
    lc: PhantomData<(L, C)>,
}

/// Any Verifiable Credential that can be interpreted as an RDF graph is a `LinkedDataCredential`.
impl<'t, 'n, N: 'n + Namespace, G: Generator<N>, L, C, T> LinkedDataCredential
    for InNamespace<'t, 'n, T, N, L, C, G>
where
    N: Namespace + TryExportQuad<N::Id, N::Id, Object<N::Id, L>, N::Id>,
    T: ssi_vc::schema::cred::VerifiableCredential<C> + treeldr_rust_prelude::rdf::Quads<N, L>,
{
    type Context = LinkedDataCredentialContext<'n, N, L, C, G>;

    type Quads<'a> = ExportQuads<'a, N, L, G, <T as treeldr_rust_prelude::rdf::Quads<N, L>>::Quads<'a>> where Self: 'a;

    fn quads<'a>(&'a self, context: &'a mut Self::Context) -> Self::Quads<'_> {
        ExportQuads(
            self.value
                .rdf_quads(context.namespace, &mut context.generator, None),
        )
    }
}

/// Wrappers that turns an RDF `Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>` into a `Quad` iterator.
pub struct ExportQuads<
    'a,
    N: Namespace,
    L,
    G,
    I: RdfIterator<N, Item = Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>>,
>(treeldr_rust_prelude::rdf::iter::Bound<'a, 'a, 'a, I, N, G>);

impl<'a, N, L, G, I> Iterator for ExportQuads<'a, N, L, G, I>
where
    N: Namespace + TryExportQuad<N::Id, N::Id, Object<N::Id, L>, N::Id>,
    G: Generator<N>,
    I: RdfIterator<N, Item = Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>>,
{
    type Item = Quad;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                Some(quad) => {
                    let namespace = self.0.namespace_mut();
                    if let Ok(quad) = namespace.try_export_quad(quad) {
                        break Some(quad);
                    }
                }
                None => break None,
            }
        }
    }
}
