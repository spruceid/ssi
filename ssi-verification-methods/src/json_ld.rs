use rdf_types::VocabularyMut;

pub trait FlattenIntoJsonLdNode<V, I, M = ()>
where
    V: VocabularyMut,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        node: &mut json_ld::Node<V::Iri, V::BlankId, M>,
    );
}

impl<V, I, M> FlattenIntoJsonLdNode<V, I, M> for ()
where
    V: VocabularyMut,
{
    fn flatten_into_json_ld_node(
        self,
        _vocabulary: &mut V,
        _interpretation: &I,
        _node: &mut json_ld::Node<<V>::Iri, <V>::BlankId, M>,
    ) {
    }
}

impl<T, V, I, M> FlattenIntoJsonLdNode<V, I, M> for Option<T>
where
    V: VocabularyMut,
    T: FlattenIntoJsonLdNode<V, I, M>,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        node: &mut json_ld::Node<<V>::Iri, <V>::BlankId, M>,
    ) {
        if let Some(t) = self {
            t.flatten_into_json_ld_node(vocabulary, interpretation, node)
        }
    }
}
