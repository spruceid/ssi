//! EdDSA Cryptosuite v2022 implementation.
//! 
//! This is the successor of the EdDSA Cryptosuite v2020.
//! 
//! See: <https://w3c.github.io/vc-di-eddsa/>

// /// Verification method for the `Ed25519Signature2020` crypto suite.
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub enum VerificationMethod {
//     /// `Multikey`.
//     Multikey(verification::method::Mulitkey),

//     /// `JsonWebKey2020`.
//     JsonWebKey2020(verification::method::JsonWebKey2020),

//     /// Deprecated verification method for the `Ed25519Signature2020` suite.
//     Ed25519VerificationKey2020(verification::method::Ed25519VerificationKey2020),
// }

// impl LinkedDataVerificationMethod for VerificationMethod {
//     fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
//         match self {
//             Self::Multikey(m) => m.quads(quads),
//             Self::JsonWebKey2020(m) => m.quads(quads),
//             Self::Ed25519VerificationKey2020(m) => m.quads(quads),
//         }
//     }
// }

// impl<V: VocabularyMut, I, M> IntoJsonLdObjectMeta<V, I, M> for VerificationMethod {
//     fn into_json_ld_object_meta(
//         self,
//         vocabulary: &mut V,
//         interpretation: &I,
//         meta: M,
//     ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
//         match self {
//             Self::Multikey(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta),
//             Self::JsonWebKey2020(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta),
//             Self::Ed25519VerificationKey2020(m) => {
//                 m.into_json_ld_object_meta(vocabulary, interpretation, meta)
//             }
//         }
//     }
// }

// impl<V: VocabularyMut, I, M> AsJsonLdObjectMeta<V, I, M> for VerificationMethod {
//     fn as_json_ld_object_meta(
//         &self,
//         vocabulary: &mut V,
//         interpretation: &I,
//         meta: M,
//     ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
//         match self {
//             Self::Multikey(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta),
//             Self::JsonWebKey2020(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta),
//             Self::Ed25519VerificationKey2020(m) => {
//                 m.as_json_ld_object_meta(vocabulary, interpretation, meta)
//             }
//         }
//     }
// }