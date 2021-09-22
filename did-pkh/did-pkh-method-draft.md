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
pkh-did    = "did:pkh:" address
address    = account_address according to [CAIP-10]
```

### Examples

Here is an example from each currently supported network, linked to a sample
JSON-LD DID document derived from each:

| Network (key type) | example (linked to sample DID document) |
|:---:|:---:|
| btc | [did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-btc.jsonld) |
| doge | [did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-doge.jsonld) |
| eth (mainnet) | [did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-eth.jsonld) |
| celo | [did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-celo.jsonld) |
| solana | [did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-sol.jsonld) |
| poly | [did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-poly.jsonld) |
| tz (tz1) | [did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz1.jsonld) |
| tz (tz2) | [did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz2.jsonld) |
| tz (tz3) | [did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz3.jsonld) |

As you can see, the did:pkh address simply consists of a prefix to identify the
namespace on which the address is valid (and could be published, but isn't
necessarily). Validity is checked according to [CAIP-10][] before
generating.   

### Networks

Note that networks (i.e., EVMs) and specific chains (i.e., ledgers, including
private DLTs and test-nets) have to be specified separately and explicitly for
all did-pkh addresses; in blockchain systems where accounts are controlled by
multiple keytypes, like Tezos, the network and chain subdomains will not be
enough to identify keytype, which must be detected from the address itself.

|account type|network id (CAIP-2) + chain id (CAIP-10)|verification method type|URL for context definition|
|---|---|---|---|
|`tz1`|`tezos:NetXdQprcVkpaWU`|Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|
|`tz`|`tezos:NetXdQprcVkpaWU`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|`tz`|`tezos:NetXdQprcVkpaWU`|P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021|
|ethereum mainnet|`eip155:1`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|celo mainnet|`eip155:42220`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|polygon mainnet|`eip155:137`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|solana|`solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ`|Ed25519VerificationKey2018|https://w3id.org/security#Ed25519VerificationKey2018|
|bitcoin mainnet|`bip122:000000000019d6689c085ae165831e93`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|
|dogecoin mainnet|`bip122:1a91e3dace36e2be3bf030a65679fe82`|EcdsaSecp256k1RecoveryMethod2020|https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020|

### Context

The following should be manually inserted into each DID Document. This will
likely change over time as new verification methods are supported, and
general-purpose methods are specified. Term definitions may be omitted from
these if they are not needed in particular DID documents.

```
{
  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
  "publicKeyJwk": {
    "@id": "https://w3id.org/security#publicKeyJwk",
    "@type": "@json"
  },
  "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
  "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
  "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
  "TezosMethod2021": "https://w3id.org/security#TezosMethod2021",
  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
}
```
## Operations

### Create

The blockchain account id is validated according to [CAIP-10][] and then appended to
`did:pkh:{network}:`, where `{network}` is the supported prefix corresponding to
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
- Initialize a DID document, *doc*, as a JSON-LD document.
- Set the `id` property of *doc* to *did*.
- Set the `@context` property of *doc* to an array,
  `["https://www.w3.org/ns/did/v1", context]`, where `context` is the [did:pkh JSON-LD context object](#context).
- Construct the verification method ID, *vm*, by appending
  "#blockchainAccountId" to *did*.
- Construct the [verification method][] object, *vmObj* as follows:
  - Insert property `id` into *vmObj* with value *vm*.
  - Look up network id *network* in the did:pkh [Networks][#networks] table, to
    get verification method type *vmType* and [CAIP-2][] chain id *chainId*. If
    there are multiple entries in the table for *network*, use one that
    matches *address*.
  - Insert property `type` into *vmObj* with value *vmType*.
  - Insert property `controller` into *vmObj* with value *did*.
  - Construct string *accountId* by concatenating *address* + "@" + *chainId*.
  - Insert property `blockchainAccountId` into *vmObj* with value *accountId*.
- Insert a property into *doc* with key name `verificationMethod` and a value of
  an array containing only *vmObj*.
- Insert a property into *doc* with key name `authentication` and a value of an
  array containing only *vm*.
- Insert a property into *doc* with key name `assertionMethod` and value of an
  array containing only *vm*.
- Construct an empty DID Resolution metadata object, *resMeta*.
- Construct an empty DID Document metadata object, *docMeta*.
- Return *resMeta*, *doc*, and *docMeta*.


### Update

No updates possible. did:pkh DID Documents are, like [did:key] documents, intended for local-only usage.

### Delete

No deletion possible. did:pkh DID Documents are, like [did:key] documents, intended for local-only usage.

## Security & Privacy Considerations (non-normative)

There are a number of security and privacy considerations that implementers will want to take into consideration when implementing this specification. These are adapted from the analogous considerations proposed by the did:key authors.

### Key Rotation Not Supported

The did:pkh method is a purely generative method, which means that updates are not supported. This can be an issue if a did:pkh is expected to be used over a long period of time. For example, if a did:pkh is ever compromised, it is not possible to rotate the compromised key. For this reason, using a did:pkh for interactions that last weeks to months is strongly discouraged.

### Deactivation Not Supported

The did:pkh method is a purely generative method, which means that deactivations and "tombstoning" are not supported internally, and would require a separate system with its own availablity, privacy, and security concerns. This can be an issue if a did:pkh is expected to be used over a long period of time. For example, if a did:pkh is ever compromised, it is not possible to deactivate the DID to stop an attacker from using it. For this reason, using a did:pkh for interactions that last weeks to months is strongly discouraged.

### Key Derivation Lacks Proof

Some implementations might utlize a key derivation function when converting from an ed25519 public key to a Curve25519 ECDH key, used in the keyAgreement verification method. It is expected that this is a relatively safe operation, but implementers might consider that there exists no mathematical proof that confirms this assumption.

### Long Term Usage is Discouraged

Since there is no support for update and deactivate for the did:pkh method, it is not possible to recover from a security compromise. For this reason, using a did:pkh for interactions that last weeks to months is strongly discouraged. Instead, the recovery, rotation, and in most cases authentication properties of the system from which the PKH originates should be relied on directly.

## Ref Impl

|Author|name of implementation|link to pkh libraries|date registered|
|:---:|:---:|:---:|:---:|
|Spruce Systems, USA|[DIDKit](https://github.com/spruceid/didkit/)|`did-pkh` crate in ssi [core library](https://github.com/spruceid/ssi/tree/main/did-pkh)|July 2,2021|

## Appendix: Legacy Support

An earlier version of this specification used more human-readable submethod
namespacing rather than referring mapping directly to the CAIP naming
convention. It also defaulted to main-net for `did:pkh:eth` in the absence of an
explicit chainID.  As the scope has grown of this project, and with forward
compatibility in mind, both of these patterns have been removed, required
explicitly naming the EVM by its registered [CAIP-2][] code and explicitly
naming the `chain_id` (as specified in [CAIP-10][]) as well.  The legacy aliases
that Spruce's implementation also supports for backwards-compatibility with
credentials already issued look like this:

| prefix | example (linked to sample DID document) |
|:---:|:---:|
| btc | [did:pkh:btc:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-btc-legacy.jsonld) |
| doge | [did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-doge-legacy.jsonld) |
| eth | [did:pkh:eth:0xb9c5714089478a327f09197987f16f9e5d936e8a](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-eth-legacy.jsonld) |
| sol | [did:pkh:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-sol-legacy.jsonld) |
| celo | [did:pkh:celo:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-celo-legacy.jsonld) |
| poly | [did:pkh:poly:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-poly-legacy.jsonld) |
| tz (tz1) | [did:pkh:tz:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz1-legacy.jsonld) |
| tz (tz2) | [did:pkh:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz2-legacy.jsonld) |
| tz (tz3) | [did:pkh:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX](https://github.com/spruceid/ssi/blob/main/did-pkh/tests/did-tz3-legacy.jsonld) |


[DID Core]: https://www.w3.org/TR/did-core/
[did:key]: https://w3c-ccg.github.io/did-method-key/
[verification method]: https://www.w3.org/TR/did-core/#verification-methods
[blockchainaccountid]: https://www.w3.org/TR/did-spec-registries/#blockchainaccountid
[CAIP-10]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
[CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
[eip712]: https://github.com/uport-project/ethereum-eip712-signature-2021-spec
