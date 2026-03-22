# QUEN.md

## Overview of the SSI Library

The SSI library is a Rust library that provides a simple and modular API to sign and verify claims exchanged between applications using Decentralized Identifiers (DIDs). The library supports two main families of verifiable claims:
- JSON Web Tokens (JWT), where claims are encoded into JSON and secured using JSON Web Signatures (JWS)
- W3C's Verifiable Credentials (VCs), a Linked-Data-based model where claims (VCs) can be interpreted as RDF datasets

The SSI library is embedded in the cross-platform `didkit` library as a core dependency.

## Unit Tests

The library's unit tests are located in the `tests/` directory. The tests cover various aspects of the library, including:
- Verification of JSON Web Signatures (JWSs) and Verifiable Credentials (VCs)
- Signature and custom claims
- Data models (VC data-model 1.1, 2.0, and a wrapper type to accept both)

The tests use the `cargo test` command to run, and they require the RDF canonicalization test suite, which is embedded as a git submodule.

## Context

The SSI library is used to sign and verify claims exchanged between applications using Decentralized Identifiers (DIDs). The library supports two main families of verifiable claims: JSON Web Tokens (JWT) and W3C's Verifiable Credentials (VCs). The library's unit tests are located in the `tests/` directory and cover various aspects of the library, including verification, signature, and data models.