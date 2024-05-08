impl<V: Vocabulary, I: Interpretation> LinkedDataResource<I, V> for CompactJWSString {
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{xsd_types::ValueRef, CowRdfTerm, RdfLiteralRef, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Borrowed(RdfTermRef::Literal(
            RdfLiteralRef::Xsd(ValueRef::String(&self.0)),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for CompactJWSString {
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        serializer.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializeSubject<I, V> for CompactJWSString
where
    V: Vocabulary,
    I: ReverseIriInterpretation<Iri = V::Iri> + ReverseLiteralInterpretation<Literal = V::Literal>,
{
    fn deserialize_subject_in<D>(
        vocabulary: &V,
        interpretation: &I,
        _dataset: &D,
        _graph: Option<&I::Resource>,
        resource: &I::Resource,
        context: linked_data::Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        D: PatternMatchingDataset<Resource = I::Resource>,
    {
        let mut literal_ty = None;
        for l in interpretation.literals_of(resource) {
            let literal = vocabulary.literal(l).unwrap();

            match literal.type_ {
                LiteralTypeRef::Any(ty) => {
                    let ty_iri = vocabulary.iri(ty).unwrap();

                    if ty_iri == linked_data::xsd_types::XSD_STRING {
                        return literal.value.parse().map_err(|_| {
                            linked_data::FromLinkedDataError::InvalidLiteral(
                                context.into_iris(vocabulary, interpretation),
                            )
                        });
                    }

                    literal_ty = Some(ty_iri)
                }
                LiteralTypeRef::LangString(_) => literal_ty = Some(RDF_LANG_STRING),
            }
        }

        match literal_ty {
            Some(ty) => Err(linked_data::FromLinkedDataError::LiteralTypeMismatch {
                context: context.into_iris(vocabulary, interpretation),
                expected: Some(linked_data::xsd_types::XSD_STRING.to_owned()),
                found: ty.to_owned(),
            }),
            None => Err(linked_data::FromLinkedDataError::ExpectedLiteral(
                context.into_iris(vocabulary, interpretation),
            )),
        }
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for CompactJWSString {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializePredicateObjects<I, V>
    for CompactJWSString
where
    V: Vocabulary,
    I: ReverseIriInterpretation<Iri = V::Iri> + ReverseLiteralInterpretation<Literal = V::Literal>,
{
    fn deserialize_objects_in<'a, D>(
        vocabulary: &V,
        interpretation: &I,
        dataset: &D,
        graph: Option<&I::Resource>,
        objects: impl IntoIterator<Item = &'a I::Resource>,
        context: linked_data::Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        I::Resource: 'a,
        D: PatternMatchingDataset<Resource = I::Resource>,
    {
        let mut objects = objects.into_iter();
        match objects.next() {
            Some(object) => {
                if objects.next().is_none() {
                    Self::deserialize_subject(vocabulary, interpretation, dataset, graph, object)
                } else {
                    Err(linked_data::FromLinkedDataError::TooManyValues(
                        context.into_iris(vocabulary, interpretation),
                    ))
                }
            }
            None => Err(linked_data::FromLinkedDataError::MissingRequiredValue(
                context.into_iris(vocabulary, interpretation),
            )),
        }
    }
}
