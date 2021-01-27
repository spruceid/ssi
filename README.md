[![](https://img.shields.io/github/workflow/status/spruceid/ssi/ci)](https://github.com/spruceid/ssi/actions?query=workflow%3Aci+branch%3Amain) [![](https://img.shields.io/badge/Rust-v1.51.0-orange)](https://www.rust-lang.org/) [![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE) [![](https://img.shields.io/twitter/follow/sprucesystems?label=Follow&style=social)](https://twitter.com/sprucesystems) 

SSI's documentation is currently packaged with the DIDKit documentation
[here](https://spruceid.dev/docs/didkit/).

# SSI

SSI provides core Verifiable Credential and Decentralized Identifier
functionality in Rust. Rust was chosen for its expressive type system, memory
safety, simple dependency web, and suitability across different platforms
including embedded systems. This library is embedded in the the cross-platform
[`didkit`](https://github.com/spruceid/didkit) library as a core dependency.

![DIDKit core components](https://spruceid.dev/assets/images/didkit-core-components-7abba2778ffe8dde24997f305e706bd8.png)

## Maturity Disclaimer
In the v0.1 release on January 27th, 2021, SSI has not yet undergone a
formal security audit and to desired levels of confidence for suitable use in
production systems. This implementation is currently suitable for exploratory
work and experimentation only. We welcome feedback on the usability,
architecture, and security of this implementation and are committed to a
conducting a formal audit with a reputable security firm before the v1.0
release.

We are setting up a process to accept contributions. Please feel free to open
issues or PRs in the interim, but we cannot merge external changes until this
process is in place.

We are also in the process of creating crates.io entries for the DIDKit and SSI
packages.

## Install

```sh
$ git clone https://github.com/spruceid/ssi .
$ cd ssi
$ git submodule update
$ cargo build
```

## Additional resources

[Rust]: https://www.rust-lang.org/
[rustup]: https://rustup.rs/
[Cargo]: https://doc.rust-lang.org/cargo/
[installing-rust]: https://doc.rust-lang.org/nightly/edition-guide/rust-2018/rustup-for-managing-rust-versions.html
