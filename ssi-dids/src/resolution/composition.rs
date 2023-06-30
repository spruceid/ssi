use std::collections::HashMap;

use crate::DIDResolver;

use super::DIDMethodResolver;

/// Compose multiple DID method resolvers into a DID resolver.
#[derive(Default)]
pub struct MethodComposition<'a> {
    methods: HashMap<String, Box<dyn 'a + DIDMethodResolver>>,
}

impl<'a> MethodComposition<'a> {
    pub fn insert(&mut self, resolver: impl 'a + DIDMethodResolver) {
        let method = resolver.method_name().to_string();
        self.methods.insert(method, Box::new(resolver));
    }
}

impl<'a> DIDResolver for MethodComposition<'a> {
    fn get_method(&self, method_name: &str) -> Option<&dyn DIDMethodResolver> {
        self.methods.get(method_name).map(|m| &**m)
    }
}

// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// impl<'a> DIDResolver for SeriesResolver<'a> {
//     /// Resolve a DID using a series of DID resolvers.
//     ///
//     /// The first DID resolution result that is not a [`methodNotSupported`][ERROR_METHOD_NOT_SUPPORTED] error is returned as the
//     /// result.
//     async fn resolve(
//         &self,
//         did: &str,
//         input_metadata: &ResolutionInputMetadata,
//     ) -> (
//         ResolutionMetadata,
//         Option<Document>,
//         Option<DocumentMetadata>,
//     ) {
//         for resolver in &self.resolvers {
//             let (res_meta, doc_opt, doc_meta_opt) = resolver.resolve(did, input_metadata).await;
//             let method_supported = match res_meta.error {
//                 None => true,
//                 Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
//             };
//             if method_supported {
//                 return (res_meta, doc_opt, doc_meta_opt);
//             }
//         }
//         (
//             ResolutionMetadata::from_error(ERROR_METHOD_NOT_SUPPORTED),
//             None,
//             None,
//         )
//     }

//     /// Resolve a DID in a representation using a series of DID resolvers.
//     async fn resolve_representation(
//         &self,
//         did: &str,
//         input_metadata: &ResolutionInputMetadata,
//     ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
//         for resolver in &self.resolvers {
//             let (res_meta, doc_data, doc_meta_opt) =
//                 resolver.resolve_representation(did, input_metadata).await;
//             let method_supported = match res_meta.error {
//                 None => true,
//                 Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
//             };
//             if method_supported {
//                 return (res_meta, doc_data, doc_meta_opt);
//             }
//         }
//         (
//             ResolutionMetadata::from_error(ERROR_METHOD_NOT_SUPPORTED),
//             Vec::new(),
//             None,
//         )
//     }

//     /// Dereference a DID URL using a series of DID resolvers (DID URL dereferencers).
//     async fn dereference(
//         &self,
//         primary_did_url: &PrimaryDIDURL,
//         input_metadata: &DereferencingInputMetadata,
//     ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
//         for resolver in &self.resolvers {
//             if let Some((deref_meta, content, content_meta)) =
//                 resolver.dereference(primary_did_url, input_metadata).await
//             {
//                 let method_supported = match deref_meta.error {
//                     None => true,
//                     Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
//                 };
//                 if method_supported {
//                     return Some((deref_meta, content, content_meta));
//                 }
//             }
//         }
//         None
//     }
// }
