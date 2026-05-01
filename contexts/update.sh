#!/bin/sh
# Note: update src/lib.rs when updating URLs/filenames in this file.
cd "$(dirname "$0")" || exit 1
exec curl \
    https://www.w3.org/2018/credentials/v1 -o w3c-2018-credentials-v1.jsonld \
    https://www.w3.org/2018/credentials/examples/v1 -o w3c-2018-credentials-examples-v1.jsonld \
    https://www.w3.org/ns/credentials/v2 -o w3c-ns-credentials-v2.jsonld \
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
    https://www.w3.org/ns/credentials/status/v1 -o w3c-credentials-status-v1.jsonld \
    https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json -o cacao-zcap-v1.jsonld \
    https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json -o jff-vc-edu-plugfest-1-context.json \
    https://openbadgespec.org/v2/context.json -o openbadges-v2.json \
    https://purl.imsglobal.org/spec/ob/v3p0/context.json -o openbadges-v3.json \
    https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.1.json -o openbadges-v3.0.1.json \
    https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json -o openbadges-v3.0.2.json \
    https://purl.imsglobal.org/spec/ob/v3p0/extensions.json -o openbadges-v3-extensions.json \
    https://playground.chapi.io/examples/alumni/alumni-v1.json -o chapi-alumni-v1.json \
    https://playground.chapi.io/examples/movieTicket/ticket-v1.json -o chapi-movie-ticket-v1.json \
    https://purl.imsglobal.org/spec/clr/v2p0/context.json -o clr-2.0.json \
    https://w3id.org/security/data-integrity/v1 -o w3id-data-integrity.json \
    https://purl.imsglobal.org/spec/ob/v3p0/context.json -o plugfest-2.json \
    https://ctx.learncard.com/boosts/1.0.0.json -o learncard-boosts-1.0.0.json \
    https://ctx.learncard.com/boosts/1.0.1.json -o learncard-boosts-1.0.1.json \
    https://ctx.learncard.com/boosts/1.0.2.json -o learncard-boosts-1.0.2.json \
    -L
