# ssi-did-test

Test vector generator for [DID Test Suite][]

## Usage

Install [Cargo][].

Clone the DID Test Suite repo:
```
git clone https://github.com/w3c/did-test-suite
```

Clone the `ssi` repo and fetch submodules:
```
git clone https://github.com/spruceid/ssi
cd ssi
git submodule update --init
````

Generate test vectors using the `generate.sh` script, passing the path to the `implementations` directory in the DID Test Suite:
```
./did-test/generate.sh ../did-test-suite/packages/did-core-test-server/suites/implementations
```

[DID Test Suite]: https://github.com/w3c/did-test-suite/
[Cargo]: https://doc.rust-lang.org/cargo/
