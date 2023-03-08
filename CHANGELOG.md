# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- [4a2b53a] Add prepare_proof function to Presentation
- [5f7d1a7] Added impl From<VCDateTime> for chrono::DateTime<Tz>.
- [4c30f1a] Add anyhow error variant (#410)
- [c29524b] Add revocation-list-2020 to contexts updater
- [3fc36d8] Add CACAO-ZCAP context
- [6a94e2b] Add ContextLoader struct and parameter
- [accabcd] Add JFF VC-EDU Plugfest 2022 context
- [351c923] Add TraceabilityAPI to Traceability context
- [24efa09] Add `did-jwk` support (#466)
- [49a0473] Add PlugFest2 context (#494)

### Changed
- [e9f15ac] Restructure (#457)

### Fixed
- [b4993a9] Fix rl2020 context filename in update script
- [82ebcd0] Fix clear_on_drop for WASM (#451)
- [d19575d] fix json-ld-normalization remote, repo has moved (#463)
- [5f635fc] Fix Clippy CI and warnings (#467)
- [c10e70e] Fix Aleo example feature (#471)
- [0580576] fix default proof type selection (#475)
- [ca8518a] Fix did-jwk name (#477)
- [c4a2051] Fix and clean up features (#479)
- [adc604d] Fix missing ssi-ldp tezos feature (#480)
- [19a177d] Fix JWK/JWS `none` alg casing (#485)
- [bb4f1a4] Fix test docs and gate it behind feature (#497)

### Other
- [4d6ffc0] Update DID method crates for ssi v0.4
- [c57b252] Use default ssi/ring in DID method crates
- [8278650] Update DID method crates
- [65cb912] Allow holderless verifiable presentation (#407)
- [f4fc478] Update readme to reflect audit (#408)
- [ab332d1] Require credentialSubject to be non-empty (#409)
- [ea4d9cf] Expose URI::as_str
- [ec31b08] Address cargo clippy warnings (#418)
- [693afbb] Use EcdsaSecp256k1RecoveryMethod2020 v2 context
- [59cd521] Auto-generate context file update PRs
- [e6d7e7b] Update contexts and add zCap v1 context file (#419)
- [46dc99b] Output key length
- [5f021a2] Deprecate unused RevocationSubject
- [2bc433a] Implement StatusList2021
- [e24fc21] Set author on update_contexts action
- [a050ab6] Update context files
- [05e229f] Update context files
- [8dc91a1] Implement ES384 sign/verify with openssl
- [68fb551] cargo fmt
- [7f66f32] :bug: Fix bad plugfest context IRI
- [0ea45bf] Make bbs optional
- [8821b4d] Sort properties in Traceability context
- [acd3f21] :bug: Fix hardcoded ssi dirname
- [2615a8d] UCAN implementation (#447)
- [992890c] cargo fmt
- [62986e0] Make compilation fail clearly when missing hashing deps (#452)
- [e108c35] Address Clippy warnings and add to CI (#456)
- [e865520] UCAN v0.9 (#455)
- [26e5275] Update documentation link and clear outdated diagram (#469)
- [da702ea] update changelog (#465)
- [3981751] Verifiable Presentation holder binding (#450)
- [b2803b0] Use renamed siwe-recap crate. (#474)
- [b6a6519] dont use "w3c" feature for gating ldp types (#476)
- [9382f9c] Various changes following JWT VC interop (#488)
- [e4d46a2] bump ipld dep for ucan (#487)
- [758348f] Use enum for proof suites (#489)
- [d5002e5] Release chores (#493)
- [b828864] Require Sync for dyn Document (#495)
- [7f3264c] Generate changelog automatically (#496)
- [3e7bebc] Upgrade `json-ld`. (#500)

### Removed
- [8b44f0f] Remove JsonWebSignature2020 RSA key length check
- [bafe7a5] Remove esrs2020-extra from contexts updater
- [bd244df] Remove PassthroughDigest and update crypto dependencies (#385)
- [7c7bd2b] Remove unused DecodeError (#482)
- [80be3ef] Remove openssl (#484)
- [b5bd02a] Remove wildcard dev dependency version (#498)
- [5392658] Remove wildcard dev dependency version (#499)

## [0.4.0] - 2022-03-02

### Added
- [4c96065] Add BBS+ Signatures 2020 context file
- [a7df2fc] Add Presentation Submission context file
- [cc592f7] Add public function for JSON-LD expansion
- [d98675e] Add RSAParams new_public function
- [3560ff2] Add test for pkh EthereumPersonalSignature2021
- [ecacedf] Add eip712 to eip712sig v1 context
- [4867386] Add Blockchain Vocabulary v1 2021 context
- [963b782] Add support for fractional (up to microseconds) timestamps on JWTClaims.
- [f0578df] Add external dependencies required in README (#359)
- [f658821] Add resolution variables to did-tezos/readme.md
- [b4d1dab] Add vDL v1 context
- [7225099] Add support for did:tz:kt1 (#363)
- [d198eb2] Add ESKeccakK-R
- [46fe985] Add script to fetch context files
- [13b5f60] Add Universal Wallet 2020 context file
- [53021bc] Add rustdoc logo and favicon
- [361e5ca] Add did:pkh for Aleo
- [cc61fbf] Add AleoSignature2021 linked data signature suite
- [685046a] Add DID operations
- [afb1fcd] Add DID method transactions
- [dcb203f] Add did:ion and Sidetree
- [a206815] Add DIDMethodError

### Changed
- [d6c989f] Move out did:pkh specification
- [ecd5af9] Refactor HTTPDIDResolver::resolve

### Fixed
- [71c6ede] Fixed typo Error::Secp256k1Parse -> Error::Secp256r1Parse
- [c9bc80e] Fix WASM compilation with http-did feature

### Other
- [c669722] Update DID method crates
- [400effa] Safer string prefix checking (#299)
- [c666c74] Improve EIP-712 type string parsing (#302)
- [a5245a9] Use CAIP-10 in did:pkh
- [85aab52] Update did:pkh implementation to use CAIP-10
- [809f242] Allow JWT VC with single-element-array as subject
- [ce45fa5] Disallow revocation list index out of bounds
- [28370d4] Prepare for doctesting bbs generators
- [ed9764d] Doctest bbs generators
- [a2ede18] Make blinding values public
- [57347f8] Use consistent error type for load_resource
- [dffe8b5] Restrict Revocation List 2020 loading to HTTPS
- [5f9647d] Default disallow example non-DID VC issuer
- [59c0881] Address cargo clippy errors and warnings
- [3edda64] Use lds-jws2020 v1 context
- [527309e] Only add jws2020 context if not already in use
- [e12aa2a] Implement Zeroize on JWK types
- [1815a99] Implement Drop on JWK param types
- [450aec3] Zeroize values during Ed25519 key generation
- [5b438cd] Use JWK::from for simpler construction
- [49198f0] Clarify p256 and k256 key generation
- [aeea9f4] Clear stack page after signing
- [8849c0c] Check proof type when matching proof objects
- [181b6fc] Default to JsonWebSignature2020 for P-256
- [a8bfe5e] Implement Ed25519Signature2020
- [1c48400] Allow encoding JWT VC without subject id
- [78cc58e] Update EthereumEip712Signature2021 property names
- [d5549ef] Catch errors in bbs module
- [3fd03bd] Allow DID document base context without www.
- [770c919] Handle official test networks out-of-the-box
- [15e9446] Mock TzKT
- [4d862f7] Write changelog for recent changes
- [ba779c0] Preserve properties when issuing JWT VC/VP
- [23ef6b1] Allow other VM types with esrs2020
- [be35734] Don't use ES256K-R for EthereumEip712Signature2021
- [220e2fb] Use SHA-256 instead of Keccak in ES256K-R
- [02dd763] Test EcdsaSecp256k1RecoverySignature2020 VC
- [f18763a] Update esrs2020 test vector
- [282c481] Justify use of transmute
- [523ac30] Use http for did:web:localhost
- [f14e9ca] Made a newtype representing NumericDate from JWT spec, which wraps f64 and does a range check to ensure that there is full microsecond precision for all valid values.
- [3ffcfac] Handled the NumericDate overflow condition.
- [b377702] Document did:tz resolution options
- [ecafe23] Adds url with serde dep to prevent downstream build errors
- [c14d0a5] ssi-contexts v0.1.2
- [2237f60] cargo fmt
- [143a0e8] Allow returing verification warnings for JWS
- [df0e380] Allow Keccak256K-R for ES256K-R legacy mode
- [9608e58] Limit maximum revocation list credential size
- [b8bb778] Implement EIP-55
- [bb08622] Verify EIP-55 in EIP-155 blockchainAccountId
- [57032b1] Use EIP-55 in did:ethr blockchainAccountId
- [130cbee] Use EIP-55 in did:pkh:eip155
- [3567792] Combine sha256 functions
- [7e5eb4d] Enable features display for docs.rs
- [60548ce] Allow issuer object with id property in JWT VC
- [7bdfa1f] Update context files
- [5ebd115] Implement did:key for RSA
- [c97028d] Detect DID Resolution Result without media type
- [0d50fc8] Factor out transforming Resolution Result
- [82f52f4] Improve rustdocs
- [881904d] Editorial updates to rustdocs
- [6a33a85] Support non-normalized ES256K
- [3b38aaa] Avoid cloning secret keys during generation
- [2579d4d] Implement did:webkey:gpg (#373)
- [fb4d8aa] Use only sequoia-openpgp/crypto-rust in did:webkey
- [8fff89a] Relax DIDMethod: DIDResolver requirement
- [369e067] Use error types in sidetree
- [992dd34] More Sidetree rustdocs
- [cd6a760] Use error type for PublicKeyJwk JWK conversion
- [f4cf545] Update context files
- [08e4f7f] ssi-contexts v0.1.3
- [ac13737] Update changelog
- [223c3ed] Implement EIP-712 type generation
- [1aac507] ssi v0.4.0

### Removed
- [5d0724f] Remove redundant assignment for seed boolean
- [e390919] Remove leading zero from RSA public key modulus
- [697e055] Remove use of PassthroughDigest in ldp
- [4165715] Remove unused error variant

## [0.3.0] - 2021-09-15

### Added
- [20c4790] Add ES256 JWS test vector
- [4f10b28] Add ES256K to alg mistmatch handling
- [b4c5e72] Add UserAgent header in requests (#209)
- [ee33867] Add p256 dependency to did-key
- [2f07a6f] Add did-webkey and SSH key parsing
- [e91f4a1] Add did:pkh:eth Eip712Signature2021 test vector
- [10af675] add basic zcap impl based on linked-data-documents
- [491db36] add basic zcap deser test
- [00ad7c0] add ZCAP proof types
- [8d53367] add proof prep and gen to deleg/invokations
- [0e8ef16] add round trip
- [49537ff] add did:example:bar to DIDExample
- [78f467b] add fail paths to round trip
- [5e1851f] add arbitrary property set in ldp options to be included in Proof
- [d06b81f] Add capability to signing input
- [e517343] add error if invoker VM missing from proof
- [503ca0e] added link to draft spec in readme for did-pkh
- [90f4fa4] Add did:pkh:celo method
- [a93d82b] Add Celo to did:pkh specification draft
- [c177fe9] added security and privacy considerations
- [5f20598] Add DID Test Suite implementation generator
- [d9a3515] Add helper function to get proof suite by type
- [32c1042] Add test vectors for linked data proof alignment
- [96f9819] Add Revocation List 2020 context
- [c20e74f] Add `did-pkh-poly` (#251)
- [7090595] Add VerificationMethodMap::get_id
- [9f7eed7] Add function to get JWK from VM map
- [21c13cc] Add EthereumEip712Signature2021 v1 context
- [0a95d1d] Add PrimaryDIDURL for dereference trait method
- [0fe8735] Add BBS Signing (#270)
- [6d82e3e] Add did:key for BLS 12381 G2 (#276)
- [9f9f874] Add struct for CAIP-2 chain id

### Changed
- [00bbb47] Move p256 and k256 test keys into files
- [c3dad47] move action type param into a default prop set type

### Fixed
- [bf21287] Fix Symmetric key type naming
- [35c24c6] Fix Eip712Signature2021 canonicalization
- [a7c8e9e] Fix use of p256 in did-key
- [4717159] fix invoker check, some clean up
- [b2ccc40] fix test values
- [5447892] Fix WASM async trait compilation
- [338a799] fix successful zcap verification result value
- [f1e6477] fix wasm tests
- [740d7be] Fix test
- [adb9e38] Fix skip serializing accept metadata option
- [5d549e6] Fix did:example:foo and did:example:bar
- [d5e18e6] Fix converting RSA JWK to public
- [9d96271] Fix Tezos CAIP-2 chain IDs

### Other
- [b547ea4] Canonicalize negative zero
- [9de1c9b] Use custom-made JWK algorithms for Tezos
- [164e238] Check for negative zero without match
- [b46f148] Use compressed P-256 did:key
- [20afbb6] Implement JWK Thumbprint
- [329999d] UnsupportedKeyType is for more than just did:key
- [bedb645] Allow using Eip712 proof with normal VM types
- [5b00fa5] Enable Eip712Signature2021 in did:pkh
- [e096201] Regenerate Eip712Signature2021 test vector
- [2c8db52] Regenerate did:ethr VC test vector
- [bd2d7c4] eip712: disallow untyped properties
- [3745b7d] Implement EthereumEip712Signature2021
- [dbb3018] Implement EthereumPersonalSignature2021
- [d0877df] Update DID context from did-spec-registries
- [f811dcc] Update DID documents context
- [b0900a6] Improve JWT support
- [a14dcb9] split zcap into delegation and invokation
- [85e4e95] one proof per zcap doc + invocation deser test
- [0e0f12a] verify invocation info against target capability
- [c56910b] use did:example for test
- [0ae8827] rename action -> capabilityAction (which is in security context)
- [7f8e46d] check proof purposes for invocation and delegation
- [8758cfa] impl to_value for zcaps, fix missing pset
- [65b7a39] Update did-tezos
- [eeacbdd] Update src/zcap.rs
- [538c921] add/use `Proof::with_options` for proof params
- [67244cf] to add draft spec .md to ssi/did-pkh
- [2082354] Update did-pkh/did-pkh-method-draft.md
- [a77bbbc] Merge pull request #189 from spruceid/feat/zcap_ld
- [1bc8109] Update DID resolution content-type handling
- [35eaabe] Update DID resolution error handling
- [0acb00a] Set contentType when returning URL in dereference
- [932d86d] Correct Ethereum mainnet chain id
- [51bf519] Correct Celo chain id
- [383cb7b] typo
- [9ecc25c] Merge pull request #231 from spruceid/fix/pkh-celo
- [0c67a4d] Support publicKeyJwk for EthereumEip712Signature
- [790adcf] Generate test vector for EthereumEIP712Signature
- [e049454] Allow time zone offsets other than "Z" in VCs
- [7d486bf] Use URI type for verificationMethod option
- [a6fecbd] Implement FromStr for URI
- [7c7fdd5] Look up proof suite by type
- [945ea98] Consolidate proof type selection
- [95f0233] Use MissingFeatures error in proof type selection
- [c2f7a5b] Only match VM URI for specific DID methods
- [e09f51a] Deprecate using key_ops to select proof type
- [a377ad5] split invocation verification into methods
- [3275587] Implement PS256
- [b1d6b0b] Default to PS256 for RSA
- [16674f5] Update example VC JWT from RS256 to PS256
- [b29a8c9] Check key size for RSA JWS
- [333dd2e] Factor out initial detached JWS decoding
- [5e74193] Validate key and algorithm for JsonWebSignature2020
- [6f8e843] Update CAIP-10 maximum lengths
- [03c39bc] Use consts for CAIP-10 min/max lengths
- [09d0341] Handle eth signatures with recovery ID starting at 0
- [1dadbd7] Regenerate example VC and VP
- [38f9c5e] Validate proof object RDF consistency
- [6e742de] Update did:pkh draft
- [3419754] Merge pull request #239 from spruceid/fix/zcap-attribute-check
- [90e3862] Update W3C Software and Document Short Notice
- [2a0a9cb] Update context files
- [597b357] Update blockchainAccountId for new CAIP-10
- [e5b05d3] Use vc-test-suite example keys and DIDs
- [5e058d5] Allow returning warnings from proof verification
- [89e35a9] Update picking proof suite for tz
- [56a4373] Pass resolver option in issue/prepare
- [4d298b3] Implement converting JWK to Tezos format
- [c188ab1] Improve JWK/VM comparison
- [8068f0d] Catch double fragment in service endpoint URL
- [092db1a] Implement JcsTezosSignature2021
- [624464b] Update changelog.md (#274)
- [1a4f426] Implement credentialStatus checking
- [267f586] Implement issuer.get_id
- [61db82d] Implement RevocationList2020 validation
- [a8d54be] Cargo format did-pkh
- [1105d7e] Update image in readme to be GH-hosted (#288)
- [683113b] Test verification method map to JWK conversion
- [97e1f08] Convert EcdsaSecp256k1VerificationKey2019 to JWK
- [535cb4b] Allow publicKeyHex in verification method map
- [a4d6684] Support public key hex values in did:ethr
- [3e77c9b] Use CAIP-30 for Solana chain id
- [313e2f8] ssi-contexts v0.1.1
- [7714898] Update changelog
- [914b316] Implement easy_resolve
- [2939455] Implement did_resolve::get_verification_methods
- [cb0509d] Ensure or pick default verification method
- [5e49e61] Use json-ld v0.4.0
- [1d59829] ssi v0.3.0

### Removed
- [7fbaa19] Remove duplicate hashing for ES256
- [23e9018] Remove dependency on tezedge_client
- [7e54c08] remove URI::Default, add ::new for Invocation/Delegation
- [c54987f] remove propset from LDPO, use an extra arg instead
- [9b512fd] Remove timestamp from generative DID methods
- [2d1dd64] remove VerifyAttrs trait req for Invocation::verify
- [9fe9a00] Remove unused dependency

## [0.2.2] - 2021-05-26

### Added
- [8307883] Add TezosSignature2021 test vector

### Fixed
- [dde695d] Fix spsig
- [2982ceb] Fix p256 feature check

### Other
- [7ce9d70] did-method-key v0.1.1
- [ad73f44] Parse sppk and p2pk
- [f505d3e] Use ES256K for tzvm2021
- [b930b7c] Update tezedge-client URL
- [c380e5a] Disable failing tz1 and tz2 tests
- [16de737] Disable test using secp256k1 if feature not set
- [f522439] Disable failing did:tz:tz2 test
- [c430be4] Verify signature in JWK in proof for tzvm2021
- [d49b83f] Factor out and test Tezos signing and decoding
- [9684e0e] Enable test for secp256k1 in did-pkh
- [394d785] ssi v0.2.2

## [0.2.1] - 2021-04-28

### Fixed
- [2e77135] Fix DID methods keywords and link

### Other
- [dc8a634] Rename did-tezos to did-tz
- [d9be61d] Prepare workspace crates for release
- [13d53a9] Implement TezosSignature2021
- [65036c6] Parse Tezos keys
- [3372040] Update links to rdf-dataset-canonicalization
- [df98fab] Replace libsecp256k1 with k256
- [f007608] Init git submodules when cloning
- [b6c8f52] ssi-contexts v0.1.0
- [2105779] ssi v0.2.1

## [0.2.0] - 2021-04-01

### Added
- [49408bb] Add new method to HTTPDIDResolver
- [f747c69] Add SeriesResolver
- [5e7ed41] Add context to proof for did:tz
- [97565f8] Add missing number 8
- [561f41f] Add secp256k1
- [44c7d45] Add secp256k1 feature to include rand dependency
- [2007ec1] Add JSON Web Signature 2020 v1 context
- [ac60fd3] Add P-256
- [1df0d98] Add proof type for tz3
- [c98fe67] Add Citizenship and Vaccination contexts
- [5467296] Add Traceability context
- [76cdb3d] Add Source::KeyAndPattern and DIDMethods::generate
- [49c0bc1] Add did-pkh
- [2fc6c61] Add did:onion

### Changed
- [75ebeed] Change authors to Spruce Systems, Inc.

### Fixed
- [cafe0ec] Fix tz1 key verification
- [ca451b3] Fix EC crv property
- [2731e2d] Fix did-ethr since VP VC is now optional
- [c2384c7] Fix EIP-712 hashing and signing
- [849934d] Fix WASM compilation for resolvers that use HTTP
- [02d2f05] Fix verification relationship with base58 example

### Other
- [5cf15af] Update json-ld
- [594b196] Depend on ssi without default features
- [debab2a] Return method-not-supported if no DID method found
- [eda6958] Allow objects in DID `@context`
- [da5d87e] Expose ResolutionResult
- [9b29088] Make DIDResolver Sync, not Sized
- [ca14efa] Implement resolveRepresentation for DIDMethods
- [f3fbf7b] Use BTreeMap instead of HashMap in property_set
- [80a3f24] Dereference DID URLs
- [fc0d50a] SeriesResolver: implement more of DIDResolver
- [9ea12dc] Update async-std
- [1cb2669] Use camelCase for DID metadata structures
- [1bc7904] HTTPDIDResolver: support Document or Result
- [129a6e0] HTTPDIDResolver: implement dereference
- [a46a8ea] Support W3ID DID v1 context URL
- [541b6d4] Update did:tz verification method type
- [e85581d] Allow setting context objects in VPs and Proofs
- [cd1d463] Use Value for Proof Context
- [5db9b31] Show id in Not Found error
- [eb4ba9f] Make sign_bytes return bytes
- [f2c5efb] Allow multiple proofs on DID document
- [99eefba] Enable ES256K for vc-test-suite driver
- [70ceb19] Use separate commands for testing secp256k1
- [01281d8] Update json-ld to allow using Rust stable
- [de1057f] Use RS256 default for RSA key
- [7a32044] Implement external signing for credential proofs
- [3ce288c] Use caip10 module for verifying tz1 JWK hash
- [9d30a00] Implement did:ethr
- [48acf2c] Support multiple verification methods in a DID doc
- [2c49d6e] Implement EIP-712-based linked data proof type
- [c38293e] Allow VP without VC, except for vc-test-suite
- [5296f8a] Error if eip712vm is requested when not supported
- [2557782] Implement Default for Presentation
- [5341c53] Encode bytes in SigningInput as base64url
- [9efc43e] Implement did:sol and SolanaMethod2021
- [0f8717e] Complete did:tz resolution (#98)
- [2865e90] Use compressed public key for tz2
- [7e9f015] Use JsonWebSignature2020 for P-256
- [22b46de] Unify signature error type
- [140639e] Use EcdsaSecp256r1Signature2019 for P-256
- [2cad7cd] Support relative DID URLs in DID documents
- [b3bc3dc] Support publicKeyBase58 for Ed25519
- [e39aab1] Allow to specify BCD url externally for did:tz
- [34140e8] Improve dereferencing objects in a DID document
- [f089227] Support publicKey DID document property
- [d6922ee] Use verification relationship for proof purpose
- [4fdc084] Update json-ld to use upstream json
- [1ecb3d9] Update Changelog
- [e3b0d0f] Namespace ci cache key
- [c48aee5] Disable failing live did-tezos tests
- [352a096] Vendor json-ld crate
- [ba22005] Increment cargo CI cache key
- [29d12d2] Put context files in separate crate
- [b61ea69] Disable cache of Cargo build artifacts
- [80afc63] Make ProofSuite object-safe
- [322a66f] Name did:key package did-method-key
- [0189060] Update ssi package metadata
- [e79a26f] Use URI for esrs2020-extra
- [33f4f1c] ssi-contexts v0.0.2
- [7bf127e] ssi v0.2.0

### Removed
- [07dbb8b] Remove workarounds for updated vc-test-suite

## [0.1.0] - 2021-02-02

### Added
- [befba95] Add stub vc-test-suite driver
- [9e2c0dc] Add Document builder using derive_builder
- [178131c] Add Document::from_json convenience method
- [f569b40] Add JWT VC support for RSA keys
- [15fa92b] Add CI workflow
- [ef0562b] Add missing skip serializing if None
- [7005daf] Add DID Resolver crate
- [728b6ed] Add RSAPublicKey type
- [2c24227] Add more ProofPurpose types
- [f747cfd] Add first tier of Tezos DID resolution (#49)
- [f75124c] added license to repository
- [474a983] Add did:web
- [6d1c92e] Add README.md
- [377273e] Add rust nightly advisory
- [8a4ee10] Add copyright notices
- [6c5b1aa] Add Changelog

### Changed
- [7cd68b5] Refactor Issuer and Context to share URI validation
- [164a7b8] Move OneOrMany into own file
- [584f295] Move ssi-vc-test into separate package
- [aa1640c] Move DID Resolution into ssi crate

### Fixed
- [3763153] Fix base64url
- [5d3cbcf] Fix IRIRef/StringLiteral escaping
- [271d4e8] Fix JWK serialization
- [4c8edc4] Fix links in README.md
- [eacf9ec] Fix verifying JWK for did:tz
- [46c8f07] Fix hyperlinks in rust docs

### Other
- [3fc6a2f] init commit
- [af4603b] Update query ABNF
- [bead4e2] Update DID Pest Grammar
- [432c87a] rustfmt
- [fc82407] Test VCs/VPs
- [f127a1f] Use raw string literals for multiline inline JSON
- [d151c1f] Test more vc-test-suite sections
- [2c95d18] vc-test-suite: test zkp
- [33cb0e5] Work around cardinality issues
- [948b7a7] Explain DER tag bytes
- [3ef2fa5] Consolidate validation
- [c184907] Implement IntoIterators for OneOrMany
- [f7d86d2] Validate JWT-embedded VC
- [f3a86a7] Implement limited VC Linked Data Proofs
- [20673ab] Error on missing modulus or exponent
- [93fadcf] Implement DER as a type instead of trait
- [5e8075a] Use Algorithm type in JWK
- [1434a5c] Use TryFrom for conversions from JWK
- [a3c0032] Use main branch
- [914bf34] DID updates
- [4a15f07] Use Workspace
- [e8063bf] Prefer &str in function arguments
- [9dd0d8c] Cache CI cargo build
- [7e4702a] Issue and verify VCs/VPs, based on to vc-http-api
- [7d6a05c] Get vc-test-suite using GitHub Action
- [cd3b768] Import jsonwebtoken
- [fe3201d] Merge changes to jsonwebtoken
- [e0fb02a] Implement Ed25519VerificationKey2018
- [8d02b7c] Implement did:key resolution for Ed25519
- [5926421] Support identifier property in credentialSubject
- [b2e3579] Use issuer/holder as default verificationMethod
- [27f0fbf] Support credential expirationDate in signing input
- [b2dbbe9] Stricter validation for ld-proofs
- [fa9239b] Support TermsOfUse
- [cd08bbf] Ed25519VerificationKey2018 -> Ed25519Signature2018
- [729f1ef] Update proof options for vc-http-api test suite
- [79d4349] Use did:key verificationMethod with "#"
- [491956c] Include subseconds in datetime serialization
- [7e79a82] Use current time to millisecond precision
- [a5d8ef5] Use simple_asn1 for DER
- [686d521] Make issue/verify async
- [cfa7646] Run CI for PR to any branch
- [691be82] Use own JWT implementation
- [74fff32] Support arbitrary JSON-LD for LD-Proofs
- [71daa26] Clippy
- [445768c] Make crypto libraries optional with features
- [b3ca90c] Use ed25519-dalek instead of ed25519-compact
- [a87e644] Update DID resolution interface
- [253c19f] Use combination crate for permutations
- [14e4aa9] proof suite: use default trait implemention
- [cd65806] Update DID properties
- [2501d7e] Parse DID URLs
- [b51faff] Implement Hash, Eq and to_public on JWK
- [373c60a] Modularize DID methods
- [23854a1] Depend on ssi without default features
- [105178e] JWK: skip serializing missing private key material
- [d14eade] Enable did:tz
- [90ae5c6] updated shield for query
- [a007324] Merge pull request #79 from spruceid/update-readme
- [65bb493] v0.1.0

### Removed
- [eca4801] Remove proof expires property
- [0197bc3] Remove jsonwebtoken
- [a2ed714] Remove Ed25519VerificationKey2018 proof type
- [60d281d] Remove unused MultiResolver

