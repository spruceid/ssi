use std::{marker::PhantomData, ops::Deref};

use rdf_types::{Generator, Namespace, Object, Quad, TryExportQuad};
use treeldr_rust_prelude::RdfIterator;

mod proof;
mod sign;
pub mod suite;
mod verification;
// mod decode;

pub use proof::*;
pub use sign::*;
pub use suite::{
    CryptographicSuite, CryptographicSuiteInput, LinkedDataCryptographicSuite,
    VerifiableCryptographicSuite,
};
pub use verification::*;
// pub use decode::RdfDecoder;

/// Data Integrity credential.
pub struct DataIntegrity<T>(T);

impl<T> DataIntegrity<T> {
    pub fn new(credential: T) -> Self {
        Self(credential)
    }
}

impl<T> Deref for DataIntegrity<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Linked Data capable credential.
pub trait LinkedDataCredential<C> {
    /// Iterator over the RDF quads defined by the credential.
    type Quads<'a>: Iterator<Item = Quad>
    where
        Self: 'a,
        C: 'a;

    /// Returns an iterator over the RDF quads defined by the credential.
    fn quads<'a>(&'a self, context: &'a mut C) -> Self::Quads<'a>;

    /// Puts the RDF graph in canonical form using URDNA2015.
    fn canonical_form(&self, context: &mut C) -> Vec<Quad> {
        let quads: Vec<_> = self.quads(context).collect();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

pub struct LinkedDataCredentialContext<'n, L, C, N, G> {
    namespace: &'n mut N,
    generator: G,
    lc: PhantomData<(L, C)>,
}

impl<'n, L, C, N, G> LinkedDataCredentialContext<'n, L, C, N, G> {
    pub fn new(namespace: &'n mut N, generator: G) -> Self {
        Self {
            namespace,
            generator,
            lc: PhantomData,
        }
    }
}

/// Any Verifiable Credential that can be interpreted as an RDF graph is a `LinkedDataCredential`.
impl<'n, N: 'n + Namespace, G: Generator<N>, L, C, T>
    LinkedDataCredential<LinkedDataCredentialContext<'n, L, C, N, G>> for T
where
    N: Namespace + TryExportQuad<N::Id, N::Id, Object<N::Id, L>, N::Id>,
    T: ssi_vc::schema::cred::VerifiableCredential<C> + treeldr_rust_prelude::rdf::Quads<N, L>,
{
    type Quads<'a> = ExportQuads<'a, N, L, G, <T as treeldr_rust_prelude::rdf::Quads<N, L>>::Quads<'a>>
    where
        Self: 'a,
        LinkedDataCredentialContext<'n, L, C, N, G>: 'a;

    fn quads<'a>(
        &'a self,
        context: &'a mut LinkedDataCredentialContext<'n, L, C, N, G>,
    ) -> Self::Quads<'_> {
        ExportQuads(self.rdf_quads(context.namespace, &mut context.generator, None))
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
