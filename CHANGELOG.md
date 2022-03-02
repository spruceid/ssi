# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Use CAIP-10 in did:pkh ([#279](https://github.com/spruceid/ssi/pull/279), [#286](https://github.com/spruceid/ssi/pull/286), [#303](https://github.com/spruceid/ssi/pull/303)).
- Use updated JsonWebSignature2020 context file ([#322](https://github.com/spruceid/ssi/pull/322)).
- Add Presentation Submission context file ([#254](https://github.com/spruceid/ssi/pull/254), [#325](https://github.com/spruceid/ssi/pull/325)).
- Expose JSON-LD expansion function ([#326](https://github.com/spruceid/ssi/pull/326)).
- Add `new_public` helper function for RSA JWK parameters ([#327](https://github.com/spruceid/ssi/pull/327)).
- Allow using `type` property as verify options ([#329](https://github.com/spruceid/ssi/pull/329)).
- Implement Ed25519Signature2020 ([#341](https://github.com/spruceid/ssi/pull/341)).
- Allow JWT VC without subject id ([#346](https://github.com/spruceid/ssi/pull/346)).
- Add Blockchain Vocabulary v1 2021 context ([#347](https://github.com/spruceid/ssi/pull/347)).
- Construct API URLs for known Tezos test networks ([#350](https://github.com/spruceid/ssi/pull/350)).
- Add Verifiable Driver's License Vocabulary context file ([#361](https://github.com/spruceid/ssi/pull/361)).
- Add Universal Wallet 2020 context file ([#383](https://github.com/spruceid/ssi/pull/383)).
- Update context files ([#375](https://github.com/spruceid/ssi/pull/375)).
- Add script to update context files ([#376](https://github.com/spruceid/ssi/pull/376)).
- Document did:tz resolution options ([#357](https://github.com/spruceid/ssi/pull/357)).
- Add support for did:tz:KT1 ([#363](https://github.com/spruceid/ssi/pull/363)).
- Support fractional timestamps in JWT ([#315](https://github.com/spruceid/ssi/pull/315)).
- Allow JWS verification to return warnings ([#367](https://github.com/spruceid/ssi/pull/367).
- Verify EIP-55 mixed-case account address checksum ([#370](https://github.com/spruceid/ssi/pull/370)).
- Allow non-normalized ES256K ([#389](https://github.com/spruceid/ssi/pull/389))
- Support Aleo `did:pkh` ([#348](https://github.com/spruceid/ssi/pull/348))
- Implement `did:webkey:gpg` resolution ([#373](https://github.com/spruceid/ssi/pull/373)).
- Implement AleoSignature2021 suite ([#360](https://github.com/spruceid/ssi/pull/360)).
- Add DID operations (create, update, recover, deactivate) ([#379](https://github.com/spruceid/ssi/pull/379))
- Add DID method transactions ([#379](https://github.com/spruceid/ssi/pull/379))
- Implement Sidetree client ([#379](https://github.com/spruceid/ssi/pull/379))
- Add `did:ion` DID method implementation ([#379](https://github.com/spruceid/ssi/pull/379))
- Added more rustdocs ([#311](https://github.com/spruceid/ssi/pull/311)).

### Changed
- Use Error types in bbs code ([#338](https://github.com/spruceid/ssi/pull/338)).
- Don't add JsonWebSignature2020 context URI to proof if already existing in credential/presentation ([#322](https://github.com/spruceid/ssi/pull/322)).
- Default to JsonWebSignature2020 for P-256
- Update EthereumEip712Signature2021 for renamed properties ([#336](https://github.com/spruceid/ssi/pull/336)).
- Allow DID document base context without www ([#349](https://github.com/spruceid/ssi/pull/349)).
- Use http for did:web:localhost ([#333](https://github.com/spruceid/ssi/pull/333)).
- Depend on specific versions of bbs and pairing-plus crates ([#334](https://github.com/spruceid/ssi/pull/334)).
- Allow additional verification method types for use with EcdsaSecp256k1RecoverySignature2020 ([#351](23ef6b16a1c1d007c4b90f4484ad3e2f6f0c6495)).
- Use SHA-256 instead of Keccak in EcdsaSecp256k1RecoverySignature2020/ES256K-R ([#351](https://github.com/spruceid/ssi/pull/351)). Signatures using Keccak can still be verified, for compatibility, but are deprecated ([#367](https://github.com/spruceid/ssi/pull/367)).
- Allow issuer object with id property in JWT VC ([#374](https://github.com/spruceid/ssi/pull/374)).
- Implement did:key for RSA ([#309](https://github.com/spruceid/ssi/pull/309))
- Detect JSON DID Resolution Result, for Sidetree REST API compatibility ([#372](https://github.com/spruceid/ssi/pull/372)).
- `DIDMethod` trait no longer requires `DIDResolver` trait. ([8fff89a](https://github.com/spruceid/ssi/commit/8fff89ad5e4d258e30667fee00ea0f33c031eaa2)).
- JWT VC timestamp range constrained by microsection precision ([#315](https://github.com/spruceid/ssi/pull/315)).

### Deprecated
- EthereumEip712Signature2021 specification deprecated properties `messageSchema` and `eip712Domain`.
- did:pkh deprecated non-CAIP-10 submethods (btc, celo, doge, eth, poly, sol, tz).
- EcdsaSecp256k1RecoverySignature2020/ES256K-R using Keccak is deprecated.

### Removed
- `did:pkh` specification moved into its own repository ([#356](https://github.com/spruceid/ssi/pull/356)).

### Fixed
- Fixed panic in string prefix checking ([#299](https://github.com/spruceid/ssi/pull/299)).
- Fixed panic in EIP-712 type string parsing ([#302](https://github.com/spruceid/ssi/pull/302)).
- Allow JWT VC with single-element array subject ([#313](https://github.com/spruceid/ssi/pull/313)).
- Address clippy errors and warnings ([#305](https://github.com/spruceid/ssi/pull/305), [#306](https://github.com/spruceid/ssi/pull/306)).
- Fix example RSA public key modulus representation ([#308](https://github.com/spruceid/ssi/pull/308)).
- Doctest BBS generator parameters ([#304](https://github.com/spruceid/ssi/pull/304)).
- Use BBS+ Signatures 2020 context file ([#324](https://github.com/spruceid/ssi/pull/324)).
- Fixed url dependency ([#365](https://github.com/spruceid/ssi/pull/365)).
- Fixed EcdsaSecp256k1RecoverySignature2020/ES256K-R hashing ([#351](https://github.com/spruceid/ssi/pull/351), [#367](https://github.com/spruceid/ssi/pull/367)).
- Don't use ES256K-R for EthereumEip712Signature2021 ([#351](https://github.com/spruceid/ssi/pull/351)).
- Preserve VC/VP properties in JWT format ([#353](https://github.com/spruceid/ssi/pull/353)).

## Security
- Restrict revocation lists to HTTPS ([#317](https://github.com/spruceid/ssi/pull/317)).
- Limit size of revocation list credentials ([#339](https://github.com/spruceid/ssi/pull/339)).
- Disallow example non-DID VC issuer outside testing ([#316](https://github.com/spruceid/ssi/pull/316)).
- Disallow out-of-bounds revocation list index ([#314](https://github.com/spruceid/ssi/pull/314)).
- Zeroize JWKs on drop ([#327](https://github.com/spruceid/ssi/pull/327)).
- Reduce exposure of private key material during signing ([#328](https://github.com/spruceid/ssi/pull/328)).
- Avoid cloning secret keys during generation ([#391](https://github.com/spruceid/ssi/pull/391)).

## [0.3.0] 2021-09-16
### Added
- Add `PrimaryDIDURL` type.
- Add `EthereumEip712Signature2021` v1 context.
- Add `VerificationMethodMap::get_id` function.
- Implement converting JWK to Tezos format.
- Add `did:pkh:poly:`.
- Use `vc-test-suite` example keys and DIDs.
- Implement Revocation List 2020 credential status checking.
- Implement `PS256` JWS algorithm.
- Work-in-progress ZCap invocation methods
- Implement `FromStr` for `URI`.
- Support `publicKeyJwk` in `EthereumEip712Signature2021`.
- Add DID Test Suite implementation generator.
- Implement `JcsTezosSignature2021`.
- Implement `EthereumPersonalSignature2021`.
- Implement `EthereumEip712Signature2021`.
- Enable `Eip712Signature2021` with `did:pkh`.
- Allow using `Eip712Signature2021` with normal VM types.
- Implement `did:webkey:`
- Implement SSH key parsing.
- Implement JWK Thumbprint.
- Add `User-Agent` header in requests.
- Add `ES256K` to algorithm mistmatch handling.
- Use custom internal JWK algorithms for Tezos signing.
- Allow returning warnings from proof verification.
- Use `MissingFeatures` error in proof type selection.
- Add `Proof::with_options` for proof params.
- Support `publicKeyHex` for `EcdsaSecp256k1VerificationKey2019`.
- Resolve `did:key:zUC7` DIDs (`Bls12381G2`)
- Add BBS+ types and functions.
- Add `did_resolve::get_verification_methods` function
- Ensure or pick default verification method during VC/VP creation.

### Changed
- Use PrimaryDIDURL in dereference trait method.
- Pass resolver option in issue/prepare functions.
- Update `blockchainAccountId` for new CAIP-10.
- Default to `PS256` for RSA signing.
- Use compressed `P-256` in `did:key`.
- Disallow untyped properties in EIP-712 messages.
- Update picking proof suite for tz.
- Update DID resolution error handling and content-type handling.
- Add arbitrary property set in LDP options to be included in Proof.

### Deprecated
- Deprecate using `key_ops` to select proof type.

### Removed
- Remove timestamp from generative DID methods.
- Removed bundled `json-ld` crate.

### Fixed
- Catch double fragment in service endpoint URL.
- Improve JWK/VM comparison.
- Use CAIP-26 for Tezos chain IDs.
- Use CAIP-30 for Solana chain ids.
- Fix converting RSA JWK to public.
- Fix `did:example:foo` and `did:example:bar`.
- Update W3C Software and Document Short Notice.
- Handle eth signatures with recovery ID starting at 0.
- Only match VM URI for specific DID methods.
- Allow time zone offsets other than "Z" in VCs.
- Improve `did:pkh` documentation and chain id handling.
- Set `contentType` when returning URL in dereference.
- Fix WASM tests.
- Fix on-chain resolution in `did-tezos`.
- Fix WASM async trait compilation.
- Improve JWT support.
- Canonicalize negative zero.
- Support public key values in `did:ethr`.
- Use updated `json-ld` crate, enabling better conformance with RDF deserialization tests.

### Security
- Validate linked data proof object RDF consistency.
- Check key size for RSA JWS
- Validate key and algorithm for `JsonWebSignature2020`.
- Verification method and proof purpose are now checked during verifiable credential issuance and verifiable presentation generation.

## [0.2.2] - 2021-05-26
### Added
- Add `ssi::tzkey::{sign_tezos, encode_tezos_signed_message, decode_tzsig}`
### Fixed
- Improve testing of Tezos signing, encoding and decoding.
- Allow using TezosSignature2021 with `LinkedDataProofs::prepare`.
- Fix parsing of `sppk` and `p2pk` Tezos signature types.
### Security
- Verify signature in `TezosSignature2021` when JWK is in proof object.

## [0.2.1] - 2021-04-28
### Added
- Add `TezosSignature2021`/`TezosMethod2021`.
- Parse Tezos-base58 keys.
### Changed
- Use `k256` instead of `libsecp256k1`.
- Update `ssi-contexts` to `v0.1.0`
### Fixed
- Fix dependency conflict between `simple_asn1` and `num-bigint`.
- Fix broken links.

## [0.2.0] - 2021-04-01
### Added
- Add function `HTTPDIDResolver::new`.
- Add `SeriesResolver` struct, for combining multiple DID resolvers in series.
- Add `DIDParameters` struct.
- Add `DIDResolver::dereference` function.
- Support W3id DID v1 context URL.
- Add `jws::sign_bytes_b64` function.
- Support `secp256k1` in `did:key`.
- Support `P-256` (Secp256r1) in `did:key`.
- Support `tz2` and `tz3` addresses in [did:tz][].
- Implement [EcdsaSecp256k1Signature2019][] linked data signature suite.
- Implement [EcdsaSecp256k1RecoveryMethod2020][] linked data signature suite.
- Implement `EcdsaSecp256r1Signature2019` linked data signature suite.
- Support [blockchainAccountId][] for certain proof types.
- Support `ES256K` in [vc-test-suite][] driver.
- Support Rust stable.
- Implement external signing for linked data proofs: add `LinkedDataProofs::prepare` function and `ProofPreparation` struct.
- Add non-registry implementation of [did:ethr][].
- Implement [EIP-712][]-based linked data signature suite.
- Add experimental `did:sol` DID method for Solana, with verification method.
- Allow VP without VC, for [DIDAuth][] (except for in [vc-test-suite][]).
- Implement `Default` for `Presentation`.
- Complete `did:tz` resolution.
- Add [Citizenship][] context.
- Add [Vaccination][] context.
- Add [DID Resolution][did-resolution-result] context.
- Add [JSON Web Signature 2020][lds-jws2020] context.
- Support HTTP(S) requests in WASM and on Android.
- Support relative DID URLs in DID documents.
- Support [publicKeyBase58][] for Ed25519.
- Added `DIDMethods::generate` function.
- Add `did:pkh` Public Key Hash DID Method.
- Add `did:onion` implementation.
- Update vc-test-suite` test driver to remove workarounds.
- Use `ssi-contexts` crate.

### Changed
- Make `ResolutionResult` struct public.
- Remove `ring` from default features.
- Use `method-not-supported` DID resolution error.
- Allow objects in `@context` property of DID document, VPs, and proofs.
- Make `DIDResolver` object-safe.
- Implement `DIDResolver::resolve_representation` for `DIDMethods`.
- Preserve key order in `ResolutionResult` `property_set`.
- Completed [DID URL Dereferencing][] implementation.
- Update `iref` and `async-std` dependency versions.
- Update DID metadata parameter names.
- Support `ResolutionResult` or DID Document in `HTTPDIDResolver` response.
- Implement DID URL dereferencing through `HTTPDIDResolver`.
- Add `Data` variant to `Content` enum.
- Change `did:tz` verification method type to `Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021`.
- Add context to `Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021` linked data proofs.
- Add name to `Error::ResourceNotFound`.
- Make `jws::sign_bytes` return bytes instead of string.
- Allow multiple proofs and multiple verification methods in a DID document
- Bundle `json-ld` crate, for `crates.io` release.
- Added `Source::KeyAndPattern` enum variant.
- Made `ProofSuite` object-safe.

### Fixed
- Fix `tz1` hashing.
- Add missing number in RDF lang subtag parsing.
- Fix name of JWK EC `crv` property.
- Update crate author fields.

### Security
- Verify [verification relationship][] for [proof purpose][].

## [0.1.0] - 2021-01-27
[Initial release with DIDKit][didkit-initial-release]
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
[Citizenship]: https://w3c-ccg.github.io/citizenship-vocab/
[DID Methods]: (https://w3c.github.io/did-core/#methods)
[DID Resolvers]: https://w3c.github.io/did-core/#dfn-did-resolvers
[DID URL Dereferencing]: https://w3c.github.io/did-core/#did-url-dereferencing
[DIDAuth]: https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
[EIP-712]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
[EcdsaSecp256k1RecoveryMethod2020]: https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/
[EcdsaSecp256k1Signature2019]: https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/
[LD-Proof]: https://w3c-ccg.github.io/ld-proofs/
[Linked data signature]: https://w3c-ccg.github.io/ld-proofs/#linked-data-signatures
[Proof Types]: https://w3c-ccg.github.io/ld-proofs/#proof-types
[Traits]: https://doc.rust-lang.org/book/ch10-02-traits.html
[Vaccination]: https://w3c-ccg.github.io/vaccination-vocab/
[Verifiable Presentations]: https://w3c.github.io/vc-data-model/#presentations-0
[blockchainAccountId]: https://www.w3.org/TR/did-spec-registries/#blockchainaccountid
[did-https]: https://w3c-ccg.github.io/did-resolution/#bindings-https
[did-resolution-result]: https://w3c-ccg.github.io/did-resolution/#did-resolution-result
[did:ethr]: https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md
[did:key]: https://w3c-ccg.github.io/did-method-key/
[did:tz]: https://did-tezos-draft.spruceid.com/
[did:web]: https://w3c-ccg.github.io/did-method-web/
[didkit-initial-release]: https://sprucesystems.medium.com/didkit-v0-1-is-live-d0ea6638dbc9
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[lds-jws2020]: https://w3c-ccg.github.io/lds-jws2020/
[plugfest-2020]: https://github.com/w3c-ccg/vc-http-api/tree/master/packages/plugfest-2020
[proof purpose]: https://w3c-ccg.github.io/ld-proofs/#proof-purpose
[publicKeyBase58]: https://www.w3.org/TR/did-core/#dfn-publickeybase58
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
[urdna-tests]: https://json-ld.github.io/rdf-dataset-canonicalization/tests/
[urdna]: https://json-ld.github.io/rdf-dataset-canonicalization/spec/
[vc-data-model]: https://w3c.github.io/vc-data-model/
[vc-http-api]: https://w3c-ccg.github.io/vc-http-api/
[vc-test-suite]: https://github.com/w3c/vc-test-suite
[verification relationship]: https://www.w3.org/TR/did-core/#dfn-verification-relationship

[Unreleased]: https://github.com/spruceid/ssi/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/spruceid/ssi/releases/tag/v0.3.0
[0.2.2]: https://github.com/spruceid/ssi/releases/tag/v0.2.2
[0.2.1]: https://github.com/spruceid/ssi/releases/tag/v0.2.1
[0.2.0]: https://github.com/spruceid/ssi/releases/tag/v0.2.0
[0.1.0]: https://github.com/spruceid/ssi/releases/tag/v0.1.0
