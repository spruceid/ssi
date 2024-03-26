#!/bin/sh
set -ex
dest=${1?Usage: generate.sh <destination>}
cd "$(dirname "$0")"
cargo build
export PATH=$(realpath ../target/debug):$PATH
cd -
cd "$dest"
ssi-did-test method key > did-key-spruce.json
ssi-did-test method web > did-web-spruce.json
ssi-did-test method tz > did-tz-spruce.json
ssi-did-test method onion > did-onion-spruce.json
ssi-did-test method pkh > did-pkh-spruce.json
ssi-did-test method webkey > did-webkey-spruce.json
ssi-did-test resolver key > resolver-spruce-key.json
ssi-did-test resolver web > resolver-spruce-web.json
ssi-did-test resolver tz > resolver-spruce-tz.json
ssi-did-test resolver onion > resolver-spruce-onion.json
ssi-did-test resolver pkh > resolver-spruce-pkh.json
ssi-did-test resolver webkey > resolver-spruce-webkey.json
ssi-did-test dereferencer key > dereferencer-spruce-key.json
ssi-did-test dereferencer web > dereferencer-spruce-web.json
ssi-did-test dereferencer tz > dereferencer-spruce-tz.json
ssi-did-test dereferencer onion > dereferencer-spruce-onion.json
ssi-did-test dereferencer pkh > dereferencer-spruce-pkh.json
ssi-did-test dereferencer webkey > dereferencer-spruce-webkey.json
