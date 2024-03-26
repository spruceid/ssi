# Data Integrity Proofs format for Verifiable Credentials

The Verifiable Credential Data Model does not, by itself, specifies how the
proof is encoded and delivered with the credential data.
This library provides the Data Integrity proof format, where the proof
is defined through Data Integrity Crypto Suites and embedded to the 
VC document using the `security#proof` property.