use rdf_types::{Namespace, Generator, Quad};

pub mod suite;

/// Linked Data capable credential.
pub trait LinkedDataCredential<N: Namespace, L, C>: treeldr_rust_prelude::rdf::Triples<N, L> {
    /// Iterator over the RDF quads defined by the credential.
    type Quads<'a, G>: Iterator<Item = Quad> where Self: 'a, N: 'a, G: 'a;

    /// Returns an iterator over the RDF quads defined by the credential.
    fn quads<'a, G>(
        &'a self,
        namespace: &'a N,
        generator: &'a mut G
    ) -> Self::Quads<'a, G>
    where
        G: Generator<N>;

    /// Puts the RDF graph in canonical form using URDNA2015.
    fn canonical_form(
        &self,
        namespace: &N,
        generator: &mut impl Generator<N>
    ) -> Vec<Quad> {
        let quads: Vec<_> = self.quads(namespace, generator).collect();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

// /// Any Verifiable Credential that can be interpreted as an RDF graph is a `LinkedDataCredential`.
// impl<N: Namespace, L, C, T: ssi_vc::schema::cred::VerifiableCredential<C> + treeldr_rust_prelude::rdf::Triples<N, L>> LinkedDataCredential<N, L, C> for T {
//     type Quads<'a, G> = IntoQuads<treeldr_rust_prelude::rdf::iter::Bound<'a, 'a, <T as treeldr_rust_prelude::rdf::Triples<N, L>>::Triples<'a>, N, G>>;

//     fn quads<'a, G>(
//         &'a self,
//         namespace: &'a N,
//         generator: &'a mut G
//     ) -> Self::Quads<'a, G>
//     where
//         G: Generator<N> {
//         IntoQuads(self.rdf_triples(namespace, generator))
//     }
// }
