# did:pkh Method Specification

Authors: Wayne Chang, Charles Lehner, Juan Caballero
Status: Draft

## Introduction

### Problem Statement

There are over hundreds of billions of on-chain, balance-holding accounts across
the major 50 or so blockchains, all secured and namespaced using similar
technologies. Almost all of these derive identifiers from hashed or otherwise
obscured public keys, which are provided at time of transaction.

These accounts are used to protect billions of dollars in assets and critical
digital infrastructure. They are also actively being piloted and used by
enterprises and governments. They are rapidly becoming a major form of shared
data infrastructure across verticals and continents.

DIDs should favor usability where possible, and it is extremely beneficial from
a security & human computer interaction perspective to have DIDs that readily
correspond to their equivalents on decentralized networks. This corresponds
neatly to end-users' understanding of what an "account" is on an existing
network.  There are knock-on security effects to having an
immediately-recognizable "address" double as a DID for usage elsewhere.  

It also allows most if not all blockchain accounts to instantly leverage an
existing identity/account and deploy a W3C Decentralized Identifier from it in a
standards-conformant way. This "DID-wrapping" of an existing identifier can be
used in combination with other DID-compatible technologies, such as W3C
Verifiable Credentials or Authorization Capabilities, and produce proper
signature-suite definitions, such as "metamask-signing" (signing according to
the [[eip712]] protocol, soon to be a work item at W3C-CCG).

### Relationship to other DID architectures

did:pkh bears many similarities to
[did:key](https://w3c-ccg.github.io/did-method-key/#introduction) except it is
optimized for identifiers derived from hashes of public keys according to
well-known algorithms (commonly referred to as "public key hashes" because in
most cases they are a public key hashed according to a standard hash function).

### Combination with other DID methods

Another difference from did:key is that did:pkh is design to have many "upgrade
paths" for DIDs deterministically generated from existing keypairs.  Namely:
- if a did:pkh is controlled by a keypair which is valid for generating a
  blockchain-published DID document according to another method (for instance,
  did:tz, did:btcr or did:ethr), its did document can be translated to the form
  of that method's documents, and it can be registered there.

## Design Goals

1. The primary goal of this method is to allow any valid blockchain address to
   "spin up" a feature-limited but valid and widely interoperable DID and DID
   Document, valid in a limited context where accounts are represented by DIDs. 
2. This method is very narrow and unopinionated to allow a wide range of
   implementations.
3. For example, the validity of each address to be wrapped in a DID is checked
   according to the [CAIP-10] standard before generating, to prevent a did:pkh
   being presented as valid that would not be on its corresponding blockchain.
   **No further validation** is assumed or provided in the reference
   implemention, but implementers may still choose to gate generation to
   on-chain accounts or balance-holding accounts as per the requirements of
   their specific use case.
4. As this method is designed for interoperability with blockchain web wallets,
   authentication and signing functions are left to the blockchain-specific
   capabilities of the wallets supported by a given implementation, "dApp", or
   context. This has implications for the degree of privacy and security that
   can be assumed. Importantly, these vary across blockchains so some use-cases
   may choose to treat PKHs differently per prefix.

## Identifier scheme

### Syntax and Interpretation

```
pkh-did    = "did:pkh:" network ":" address
network    = network identitifer according to the did:pkh Networks Table
address    = account_address according to [CAIP-10]
```

### Examples

Here is an example from each currently supported network, linked to a sample
JSON-LD DID document derived from each:

| prefix | example (linked to sample DID document) |
|:---:|:---:|
| btc | [did:pkh:btc:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-btc.jsonld) |
| doge | [did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-doge.jsonld) |
| eth | [did:pkh:eth:0xb9c5714089478a327f09197987f16f9e5d936e8a](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-eth.jsonld) |
| sol | [did:pkh:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-sol.jsonld) |
| tz (tz1) | [did:pkh:tz:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz1.jsonld) |
| tz (tz2) | [did:pkh:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz2.jsonld) |
| tz (tz3) | [did:pkh:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz3.jsonld) |

As you can see, the did:pkh address simply consists of a prefix to identify the
namespace on which the address is valid (and could be published, but isn't
necessarily). Validity is checked according to the [[CAIP-10]] standard before
generating.   

### Networks

*Note: Unlike
[DID:Ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier)
which defaults to mainnet but can accept an additional prefix for other
networks, or [DID:BTCR](https://w3c-ccg.github.io/didm-btcr/#txref) which does
not specify a network and leaves network selection/discovery to implementations,
did:pkh currently defaults to mainnet (or equivalent) on every supported
blockchain without a mechanism to override and select alternatives.*


|network id|CAIP-2 chain id|verification method type|URL for context definition|
|---|---|---|---|
|`tz` (tz1)|`tezos:mainnet`|Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|
|`tz` (tz2)|`tezos:mainnet`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|`tz` (tz3)|`tezos:mainnet`|P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|
|`eth`|`eip155:1`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|`sol`|`solana`|Ed25519VerificationKey2018|https://w3id.org/security#Ed25519VerificationKey2018|
|`btc`|`bip122:000000000019d6689c085ae165831e93`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|`doge`|`bip122:1a91e3dace36e2be3bf030a65679fe82`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|

### Context

The following should be manually inserted into each DID Document. This will
likely change over time as new verification methods are supported, and
general-purpose methods are specified.

```
{
  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
  "publicKeyJwk": {
    "@id": "https://w3id.org/security#publicKeyJwk",
    "@type": "@json"
  },
  "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
  "TezosMethod2021": "https://w3id.org/security#TezosMethod2021",
  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
}
```
## Operations

### Create

The blockchain account is validated according to [[caip]] and then appended to
`did:pkh:{network}`, where `network` is the supported prefix corresponding to
the blockchain where it is valid.

### Read (Resolve)

Resolution implements the following interface defined in [DID Core][]:
```
resolve(did, resolutionOptions) →
   « didResolutionMetadata, didDocument, didDocumentMetadata »
```

Construct the DID Document for *did* as follows:
- Parse the DID into its network id, *network* and account address, *address*,
  according to Syntax and Interpretation above.
- Initialize a DID document, *doc*, as a JSON-LD document, with `id` property
  set to *did* and `@context` property set to `["https://www.w3.org/ns/did/v1",
  "https://TODO.spruceid.com/TODO/v1"]`
    - the contents of the latter context can be added manually if the above is
      unavailable in the implementation process or cannot be made available at
      runtime; see above in section [context](#context).
- Construct the verification method ID, *vm*, by appending
  "#blockchainAccountId" to *did*.
- Construct the verification method object, *vmObj* as follows:
  - define `id` as *vm* with `#blockchainAccountId` appended
  - define `type` using the appropriate [[vM type]] value listed above per
    blockchain/address type (see [networks](#networks) section)
  - define `controller` as *vm*
  - define `blockchainAccountId` as *vm* with `@` and the appropriate [[caip]]
    chain id listed above per blockchain (see [networks](#networks) section)
- Insert a property into *doc* with key name `verificationMethod` and a value of
  an array containing only *vmObj*.
- Insert a property into *doc* with key name `authentication` and a value of an
  array containing only *vm*.
- Insert a property into *doc* with key name `assertionMethod` and value of an
  array containing only *vm*.
- Construct a DID Resolution metadata object, *resMeta*.
    - Set the `content-type` property of *resMeta* to "application/did+ld+json".
- Construct a DID Document metadata object, *docMeta*.
    - Set the `created` property of *docMeta* to the current time, in the format
      according to [DID
      Core](https://www.w3.org/TR/did-core/#did-document-metadata).
- Return *resMeta*, *doc*, and *docMeta*.


### Update

No updates possible. did:pkh DID Documents are, like [did:key] documents, intended for local-only usage.

### Delete

No deletion possible. did:pkh DID Documents are, like [did:key] documents, intended for local-only usage.

## Security & Privacy

## Ref Impl

|Author|name of implementation|link to pkh libraries|date registered|
|:---:|:---:|:---:|:---:|
|Spruce Systems, USA|[DIDKit](https://github.com/spruceid/didkit/)|`did-pkh` crate in ssi [core library](https://github.com/spruceid/ssi/tree/main/did-pkh)|July 2,2021|

[did-core]: https://www.w3.org/TR/did-core/
[did:key]: https://w3c-ccg.github.io/did-method-key/
[vm type]: https://www.w3.org/TR/did-core/#verification-methods
[blockchainaccountid]: https://www.w3.org/TR/did-spec-registries/#blockchainaccountid
[caip-10]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
[eip712]: https://github.com/uport-project/ethereum-eip712-signature-2021-spec
