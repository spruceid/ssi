use crate::{
    did,
    document::representation::MediaType,
    resolution::{Error, Options, Output},
    DIDResolver, StaticDIDResolver, DID,
};

const DOC_JSON_FOO: &str = include_str!("../tests/vectors/did-example-foo.json");
const DOC_JSON_BAR: &str = include_str!("../tests/vectors/did-example-bar.json");
const DOC_JSON_12345: &str = include_str!("../tests/vectors/did-example-12345.json");
const DOC_JSON_AABB: &str = include_str!("../tests/vectors/lds-eip712-issuer.json");

// For vc-test-suite
const DOC_JSON_TEST_ISSUER: &str = include_str!("../tests/vectors/did-example-test-issuer.json");
const DOC_JSON_TEST_HOLDER: &str = include_str!("../tests/vectors/did-example-test-holder.json");

/// An implementation of `did:example`.
///
/// For use with [VC Test Suite](https://github.com/w3c/vc-test-suite/) and in other places.
pub struct ExampleDIDResolver(StaticDIDResolver);

impl ExampleDIDResolver {
    pub fn new() -> Self {
        let mut r = StaticDIDResolver::new();

        r.insert(
            did!("did:example:foo").to_owned(),
            Output::from_content(
                DOC_JSON_FOO.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        r.insert(
            did!("did:example:bar").to_owned(),
            Output::from_content(
                DOC_JSON_BAR.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        r.insert(
            did!("did:example:12345").to_owned(),
            Output::from_content(
                DOC_JSON_12345.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        r.insert(
            did!("did:example:aaaabbbb").to_owned(),
            Output::from_content(
                DOC_JSON_AABB.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        r.insert(
            did!("did:example:0xab").to_owned(),
            Output::from_content(
                DOC_JSON_TEST_ISSUER.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        r.insert(
            did!("did:example:ebfeb1f712ebc6f1c276e12ec21").to_owned(),
            Output::from_content(
                DOC_JSON_TEST_HOLDER.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );

        Self(r)
    }
}

impl Default for ExampleDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for ExampleDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        self.0.resolve_representation(did, options).await
    }
}
