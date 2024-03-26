#!/bin/sh
# Note: update src/lib.rs when updating URLs/filenames in this file.
cd "$(dirname "$0")" || exit 1
exec curl \
	https://www.w3.org/2018/credentials/v1 -o w3c-2018-credentials-v1.jsonld \
	https://www.w3.org/2018/credentials/examples/v1 -o w3c-2018-credentials-examples-v1.jsonld \
	https://www.w3.org/ns/odrl.jsonld -o w3c-odrl.jsonld \
	https://schema.org/docs/jsonldcontext.jsonld -o schema.org.jsonld \
	https://w3id.org/security/v1 -o w3id-security-v1.jsonld \
	https://w3id.org/security/v2 -o w3id-security-v2.jsonld \
	https://www.w3.org/ns/did/v1 -o w3c-did-v1.jsonld \
	https://w3id.org/did-resolution/v1 -o w3c-did-resolution-v1.jsonld \
	https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld -o dif-lds-ecdsa-secp256k1-recovery2020-0.0.jsonld \
	https://w3id.org/security/suites/secp256k1recovery-2020/v2 -o w3id-secp256k1recovery2020-v2.jsonld \
	https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json -o lds-jws2020-v1.jsonld \
	https://w3id.org/security/suites/jws-2020/v1 -o w3id-jws2020-v1.jsonld \
	https://w3id.org/security/suites/ed25519-2020/v1 -o w3id-ed25519-signature-2020-v1.jsonld \
	https://w3id.org/security/suites/blockchain-2021/v1 -o w3id-blockchain-2021-v1.jsonld \
	https://w3id.org/citizenship/v1 -o w3c-ccg-citizenship-v1.jsonld \
	https://w3id.org/vaccination/v1 -o w3c-ccg-vaccination-v1.jsonld \
	https://w3id.org/traceability/v1 -o w3c-ccg-traceability-v1.jsonld \
	https://w3id.org/security/bbs/v1 -o bbs-v1.jsonld \
	https://identity.foundation/presentation-exchange/submission/v1 -o presentation-submission.jsonld \
	https://w3id.org/vdl/v1 -o w3id-vdl-v1.jsonld \
	https://w3id.org/wallet/v1 -o w3id-wallet-v1.jsonld \
	https://w3id.org/zcap/v1 -o w3id-zcap-v1.jsonld \
	https://w3id.org/vc-revocation-list-2020/v1 -o w3id-vc-revocation-list-2020-v1.jsonld \
	https://w3id.org/vc/status-list/2021/v1 -o w3id-vc-status-list-2021-v1.jsonld \
	https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json -o cacao-zcap-v1.jsonld \
	https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json -o jff-vc-edu-plugfest-1-context.json \
	-L
