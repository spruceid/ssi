# SSI Contexts

[JSON-LD context][] files related to [Verifiable Credentials][], [Decentralized Identifiers][], and [Linked Data Proofs][]. These contexts are used in [`ssi`](../README.md) but are packaged separately because their licenses differ from `ssi`'s license.

[JSON-LD context]: https://www.w3.org/TR/json-ld11/#the-context
[Verifiable Credentials]: https://www.w3.org/TR/vc-data-model/
[Decentralized Identifiers]: https://www.w3.org/TR/did-core/
[Linked Data Proofs]: https://w3c-ccg.github.io/ld-proofs/

## Updating

Sometimes context files change over time. This crate aims to keep up to date with upstream changes in the context files it contains. To manually re-fetch the context files, run the script [update.sh](./update.sh) in the source directory.

## Licenses

The licenses of the context files are summarized in the following table. For more details, see the [LICENSES.md](./LICENSES.md) file.

Files|License
-|-
W3C context files|[W3C Software and Document Notice and License](https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document).
Schema.org context files|[Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)](https://creativecommons.org/licenses/by-sa/3.0/)
[DIF](https://identity.foundation/) context files|[Apache License, Version 2.0](http://www.apache.org/licenses/)
