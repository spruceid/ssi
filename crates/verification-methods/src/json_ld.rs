use rdf_types::VocabularyMut;

pub trait FlattenIntoJsonLdNode<V, I>
where
    V: VocabularyMut,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        node: &mut json_ld::Node<V::Iri, V::BlankId>,
    );
}

impl<V, I> FlattenIntoJsonLdNode<V, I> for ()
where
    V: VocabularyMut,
{
    fn flatten_into_json_ld_node(
        self,
        _vocabulary: &mut V,
        _interpretation: &I,
        _node: &mut json_ld::Node<<V>::Iri, <V>::BlankId>,
    ) {
    }
}

impl<T, V, I> FlattenIntoJsonLdNode<V, I> for Option<T>
where
    V: VocabularyMut,
    T: FlattenIntoJsonLdNode<V, I>,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        node: &mut json_ld::Node<<V>::Iri, <V>::BlankId>,
    ) {
        if let Some(t) = self {
            t.flatten_into_json_ld_node(vocabulary, interpretation, node)
        }
    }
}
