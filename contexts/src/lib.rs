// Note: update ../update.sh when updating URLs/filenames in this file.

/// <https://www.w3.org/2018/credentials/v1>
pub const CREDENTIALS_V1: &str = include_str!("../w3c-2018-credentials-v1.jsonld");
/// <https://www.w3.org/ns/credentials/v2>
pub const CREDENTIALS_V2: &str = include_str!("../w3c-ns-credentials-v2.jsonld");
/// <https://www.w3.org/2018/credentials/examples/v1>
pub const CREDENTIALS_EXAMPLES_V1: &str =
    include_str!("../w3c-2018-credentials-examples-v1.jsonld");
/// <https://www.w3.org/ns/credentials/examples/v2>
pub const CREDENTIALS_EXAMPLES_V2: &str = include_str!("../w3c-ns-credentials-examples-v2.jsonld");
/// <https://www.w3.org/ns/odrl.jsonld>
pub const ODRL: &str = include_str!("../w3c-odrl.jsonld");
/// <https://schema.org/>
pub const SCHEMA_ORG: &str = include_str!("../schema.org.jsonld");
/// <https://w3id.org/security/v1>
pub const SECURITY_V1: &str = include_str!("../w3id-security-v1.jsonld");
/// <https://w3id.org/security/v2>
pub const SECURITY_V2: &str = include_str!("../w3id-security-v2.jsonld");
/// <https://www.w3.org/ns/did/v1>
pub const DID_V1: &str = include_str!("../w3c-did-v1.jsonld");
/// <https://w3id.org/did-resolution/v1>
pub const DID_RESOLUTION_V1: &str = include_str!("../w3c-did-resolution-v1.jsonld");
#[deprecated(note = "Use W3ID_ESRS2020_V2 instead")]
/// <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld>
pub const DIF_ESRS2020: &str = include_str!("../dif-lds-ecdsa-secp256k1-recovery2020-0.0.jsonld");
/// <https://w3id.org/security/suites/secp256k1recovery-2020/v2>
pub const W3ID_ESRS2020_V2: &str = include_str!("../w3id-secp256k1recovery2020-v2.jsonld");
/// <https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json>
pub const LDS_JWS2020_V1: &str = include_str!("../lds-jws2020-v1.jsonld");
/// <https://w3id.org/security/suites/jws-2020/v1>
pub const W3ID_JWS2020_V1: &str = include_str!("../w3id-jws2020-v1.jsonld");
/// <https://w3id.org/security/suites/ed25519-2020/v1>
pub const W3ID_ED2020_V1: &str = include_str!("../w3id-ed25519-signature-2020-v1.jsonld");
/// <https://w3id.org/security/multikey/v1>
pub const W3ID_MULTIKEY_V1: &str = include_str!("../w3id-multikey-v1.jsonld");
/// <https://w3id.org/security/data-integrity/v1>
pub const W3ID_DATA_INTEGRITY_V1: &str = include_str!("../w3id-data-integrity-v1.jsonld");
/// <https://w3id.org/security/suites/blockchain-2021/v1>
pub const BLOCKCHAIN2021_V1: &str = include_str!("../w3id-blockchain-2021-v1.jsonld");
/// <https://w3id.org/citizenship/v1>
pub const CITIZENSHIP_V1: &str = include_str!("../w3c-ccg-citizenship-v1.jsonld");
/// <https://w3id.org/vaccination/v1>
pub const VACCINATION_V1: &str = include_str!("../w3c-ccg-vaccination-v1.jsonld");
/// <https://w3id.org/traceability/v1>
pub const TRACEABILITY_V1: &str = include_str!("../w3c-ccg-traceability-v1.jsonld");
/// <https://w3id.org/vc-revocation-list-2020/v1>
pub const REVOCATION_LIST_2020_V1: &str = include_str!("../w3id-vc-revocation-list-2020-v1.jsonld");
/// <https://w3id.org/vc/status-list/v1>
pub const STATUS_LIST_2021_V1: &str = include_str!("../w3id-vc-status-list-2021-v1.jsonld");
/// <https://demo.spruceid.com/EcdsaSecp256k1RecoverySignature2020/esrs2020-extra-0.0.jsonld>
#[deprecated(note = "Use W3ID_ESRS2020_V2 instead")]
pub const ESRS2020_EXTRA: &str = include_str!("../esrs2020-extra-0.0.jsonld");
/// <https://w3id.org/security/bbs/v1>
pub const BBS_V1: &str = include_str!("../bbs-v1.jsonld");
pub const EIP712SIG_V0_1: &str = include_str!("../eip712sig-v0.1.jsonld");
pub const EIP712SIG_V1: &str = include_str!("../eip712sig-v1.jsonld");
/// <https://identity.foundation/presentation-exchange/submission/v1>
pub const PRESENTATION_SUBMISSION_V1: &str = include_str!("../presentation-submission.jsonld");
/// <https://w3id.org/vdl/v1>
pub const VDL_V1: &str = include_str!("../w3id-vdl-v1.jsonld");
/// <https://w3id.org/wallet/v1>
pub const WALLET_V1: &str = include_str!("../w3id-wallet-v1.jsonld");
/// <https://w3id.org/zcap/v1>
pub const ZCAP_V1: &str = include_str!("../w3id-zcap-v1.jsonld");
/// <https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json>
pub const CACAO_ZCAP_V1: &str = include_str!("../cacao-zcap-v1.jsonld");
/// <https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json>
pub const JFF_VC_EDU_PLUGFEST_2022: &str = include_str!("../jff-vc-edu-plugfest-1-context.json");
pub const DID_CONFIGURATION_V0_0: &str = include_str!("../did-configuration-v0.0.jsonld");
pub const JFF_VC_EDU_PLUGFEST_2022_2: &str = include_str!("../jff-vc-edu-plugfest-2-context.json");

pub const TZ_V2: &str = include_str!("../tz-2021-v2.jsonld");
pub const TZVM_V1: &str = include_str!("../tzvm-2021-v1.jsonld");
pub const TZJCSVM_V1: &str = include_str!("../tzjcsvm-2021-v1.jsonld");
pub const EIP712VM: &str = include_str!("../eip712vm.jsonld");
pub const EPSIG_V0_1: &str = include_str!("../epsig-v0.1.jsonld");
pub const SOLVM: &str = include_str!("../solvm.jsonld");
pub const ALEOVM: &str = include_str!("../aleovm.jsonld");
