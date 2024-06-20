# did-tz

Rust implementation of the [did:tz][] DID Method, based on the [ssi][] library.

## Method-specific Resolution Options

As per the [DID Tezos specific](https://did-tezos.spruceid.com/#tiered-did-resolution),
DID resolution for did-tezos is always tiered, and in some use-cases this requires
passing the did-tz resolver in ssi some
[Resolution Metadata](https://w3c-ccg.github.io/did-resolution/#output-resolutionmetadata).
These properties are as follows:
- `tzkt_url`: Custom indexer endpoint URL
- `updates`: [Off-Chain DID Document Updates](https://did-tezos.spruceid.com/#off-chain-did-document-updates),
   aka "DID Document patches", as specified in the Tezos DID Method Specification.
- `public_key`: a Public key in Base58 format ([publicKeyBase58](https://w3c-ccg.github.io/security-vocab/#publicKeyBase58))
   to add to a [derived DID document (implicit resolution)](https://did-tezos.spruceid.com/#deriving-did-documents)
   where no look-up mechanism is available in ssi.

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/)

[did:tz]: https://did-tezos.spruceid.com/
[ssi]: https://github.com/spruceid/ssi/
