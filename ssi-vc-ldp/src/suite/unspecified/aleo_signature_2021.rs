/// Aleo Signature 2021
///
/// Linked data signature suite using [Aleo](crate::aleo).
///
/// # Suite definition
///
/// Aleo Signature 2021 is a [Linked Data Proofs][ld-proofs] signature suite consisting of the
/// following algorithms:
///
/// |         Parameter          |               Value               |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |id                          |https://w3id.org/security#AleoSignature2021|[this document](#)  |
/// |[canonicalization algorithm]|https://w3id.org/security#URDNA2015|[RDF Dataset Normalization 1.0][URDNA2015]|
/// |[message digest algorithm]  |[SHA-256]                          |[RFC4634]                   |
/// |[signature algorithm]       |Schnorr signature with [Edwards BLS12] curve|[Aleo Documentation - Accounts][aleo-accounts]|
///
/// The proof object must contain a [proofValue] property encoding the signature in
/// [Multibase] format.
///
/// ## Verification method
///
/// Aleo Signature 2021 may be used with the following verification method types:
///
/// |            Name            |                IRI                |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |       AleoMethod2021       |https://w3id.org/security#AleoMethod2021|   [this document](#)  |
/// |BlockchainVerificationMethod2021|https://w3id.org/security#BlockchainVerificationMethod2021|[Blockchain Vocabulary v1][blockchainvm2021]
///
/// The verification method object must have a [blockchainAccountId] property, identifying the
/// signer's Aleo
/// account address and network id for verification purposes. The chain id part of the account address
/// identifies an Aleo network as specified in the proposed [CAIP for Aleo Blockchain
/// Reference][caip-aleo-chain-ref]. Signatures use parameters defined per network. Currently only
/// network id "1" (CAIP-2 "aleo:1" / [Aleo Testnet I][testnet1]) is supported. The account
/// address format is documented in [Aleo
/// documentation](https://developer.aleo.org/aleo/concepts/accounts#account-address).
///
/// [message digest algorithm]: https://w3id.org/security#digestAlgorithm
/// [signature algorithm]: https://w3id.org/security#signatureAlgorithm
/// [canonicalization algorithm]: https://w3id.org/security#canonicalizationAlgorithm
/// [ld-proofs]: https://w3c-ccg.github.io/ld-proofs/
/// [proofValue]: https://w3id.org/security#proofValue
/// [Multibase]: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
/// [URDNA2015]: https://json-ld.github.io/rdf-dataset-canonicalization/spec/
/// [RFC4634]: https://www.rfc-editor.org/rfc/rfc4634 "US Secure Hash Algorithms (SHA and HMAC-SHA)"
/// [SHA-256]: http://www.w3.org/2001/04/xmlenc#sha256
/// [Edwards BLS12]: https://developer.aleo.org/autogen/advanced/the_aleo_curves/edwards_bls12
/// [aleo-accounts]: https://developer.aleo.org/aleo/concepts/accounts
/// [blockchainvm2021]: https://w3id.org/security/suites/blockchain-2021#BlockchainVerificationMethod2021
/// [blockchainAccountId]: https://w3c-ccg.github.io/security-vocab/#blockchainAccountId
/// [caip-aleo-chain-ref]: https://github.com/ChainAgnostic/CAIPs/pull/84
/// [testnet1]: https://developer.aleo.org/testnet/getting_started/overview/
pub struct AleoSignature2021;
