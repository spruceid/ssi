# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Issuing and verifying [LD-Proof][] and JWT [Verifiable Credentials][vc-data-model] and [Verifiable Presentations][].
- Testing with [VC Test Suite][vc-test-suite].
- [Linked data signature][] types [RsaSignature2018](https://w3c-ccg.github.io/lds-rsa2018/) and [Ed25519Signature2018](https://w3c-ccg.github.io/lds-ed25519-2018/).
- Testing with [VC HTTP API][vc-http-api] [`plugfest-2020` Test Suite](plugfest-2020).
- Resolution of [did:key][], [did:web][], and [did:tz][] (layer 1) DIDs.
- [Traits][] for [DID Methods][] and [DID Resolvers][], Linked Data Documents and [Proof Suites (Types][Proof Types].
- [DID Resolution HTTP(S) Binding][did-https].
- Partial implementation of [DID URL Dereferencing][].
- [JSON Web Key (JWK)][rfc7517] representation of [RSA][rfc8017] and [Ed25519][rfc8037] keys.
- [JSON Web Algorithms (JWA)][rfc7518] `RS256` and `EdDSA` (Ed25519).
- Ed25519 keypair generation.
- Deriving [did:key][] and [did:tz][] DIDs from Ed25519 keypairs.
- JWK to DER ([ASN.1][]) conversion.
- JWK conversion for [ring][], [ed25519-dalek][], and [rsa][].
- [JSON Web Token (JWT)][rfc7519] encoding and decoding.
- [JSON Web Signature (JWS)][rfc7515] signing and verifying, including [Unencoded Payload Option][rfc7797].
- [JSON-LD to RDF Deserialization][toRdf]. Tested with [JSON-LD Test Suite test cases][toRdf-tests], with unpassing tests identified.
- [RDF Dataset Normalization (URDNA2015)][urdna]. Tested with [RDF Dataset Normalization Test Cases][urdna-tests].
- Bundled JSON-LD context files, lazily parsed.
- Apache License, Version 2.0.
- Copyright notices.

[ASN.1]: https://webstore.ansi.org/Standards/ISO/ISOIEC88252015
[DID Methods]: (https://w3c.github.io/did-core/#methods)
[DID Resolvers]: https://w3c.github.io/did-core/#dfn-did-resolvers
[DID URL Dereferencing]: https://w3c.github.io/did-core/#did-url-dereferencing
[LD-Proof]: https://w3c-ccg.github.io/ld-proofs/
[Linked data signature]: https://w3c-ccg.github.io/ld-proofs/#linked-data-signatures
[Proof Types]: https://w3c-ccg.github.io/ld-proofs/#proof-types
[Traits]: https://doc.rust-lang.org/book/ch10-02-traits.html
[Verifiable Presentations]: https://w3c.github.io/vc-data-model/#presentations-0
[did-https]: https://w3c-ccg.github.io/did-resolution/#bindings-https
[did:key]: https://w3c-ccg.github.io/did-method-key/
[did:tz]: https://did-tezos-draft.spruceid.com/
[did:web]: https://w3c-ccg.github.io/did-method-web/
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[plugfest-2020]: https://github.com/w3c-ccg/vc-http-api/tree/master/packages/plugfest-2020
[rfc7515]: https://tools.ietf.org/html/rfc7515
[rfc7517]: https://tools.ietf.org/html/rfc7517
[rfc7518]: https://tools.ietf.org/html/rfc7518
[rfc7519]: https://tools.ietf.org/html/rfc7519
[rfc7797]: https://tools.ietf.org/html/rfc7797
[rfc8017]: https://tools.ietf.org/html/rfc8017
[rfc8037]: https://tools.ietf.org/html/rfc8037
[ring]: https://github.com/briansmith/ring
[rsa]: https://github.com/RustCrypto/RSA
[toRdf-tests]: https://w3c.github.io/json-ld-api/tests/toRdf-manifest.html
[toRdf]: https://w3c.github.io/json-ld-api/#rdf-serialization-deserialization-algorithms
[urdna-tests]: https://json-ld.github.io/normalization/tests/
[urdna]: https://json-ld.github.io/normalization/spec/
[vc-data-model]: https://w3c.github.io/vc-data-model/
[vc-http-api]: https://w3c-ccg.github.io/vc-http-api/
[vc-test-suite]: https://github.com/w3c/vc-test-suite

[Unreleased]: https://github.com/spruceid/ssi/commits/main
