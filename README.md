[![](https://img.shields.io/github/actions/workflow/status/spruceid/ssi/build.yml?branch=main)](https://github.com/spruceid/ssi/actions?query=workflow%3Aci+branch%3Amain)
[![](https://img.shields.io/badge/Rust-v1.66.0-orange)](https://www.rust-lang.org/)
[![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE)
[![](https://img.shields.io/twitter/follow/spruceid?label=Follow&style=social)](https://twitter.com/spruceid)

SSI's documentation is currently packaged with the DIDKit documentation
[here](https://spruceid.dev/didkit/didkit/).

# SSI

SSI provides core Verifiable Credential and Decentralized Identifier
functionality in Rust. Rust was chosen for its expressive type system, memory
safety, simple dependency web, and suitability across different platforms
including embedded systems. This library is embedded in the the cross-platform
[`didkit`](https://github.com/spruceid/didkit) library as a core dependency.

## Security Audits

ssi has undergone the following security reviews:
- [March 14th, 2022 - Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/SpruceID.pdf) | [Summary of Findings](https://blog.spruceid.com/spruce-completes-first-security-audit-from-trail-of-bits/)

We are setting up a process to accept contributions. Please feel free to open
issues or PRs in the interim, but we cannot merge external changes until this
process is in place.

## Install

### Crates.io

```
ssi = "0.4"
```

### From Source

```sh
$ git clone https://github.com/spruceid/ssi
$ cd ssi
$ git submodule update --init
$ cargo build
```

## Additional resources

- [Rust](https://www.rust-lang.org/)
- [rustup](https://rustup.rs/)
- [Cargo](https://doc.rust-lang.org/cargo/)
