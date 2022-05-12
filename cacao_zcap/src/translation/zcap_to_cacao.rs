use std::str::FromStr;

use cacaos::siwe::TimeStamp;
use cacaos::{Payload, SignatureScheme, Version as CacaoVersion, CACAO};
use iri_string::types::UriString;
use libipld::cbor::DagCbor;
use ssi::{
    jsonld::SECURITY_V2_CONTEXT,
    vc::{Proof, ProofPurpose, URI},
    zcap::{Context, Contexts, Delegation},
};
use thiserror::Error;

use crate::{
    cacao_cid_uuid, CacaoZcapExtraProps, CacaoZcapProofConvertError, CacaoZcapProofExtraProps,
    CacaoZcapStatement, CapToResourceError, ZcapRootURN, ZcapRootURNParseError, CONTEXT_URL_V1,
    DELEGATION_TYPE_2022, PROOF_TYPE_2022,
};

/// Convert a zcap delegation to a CACAO
pub fn zcap_to_cacao<S: SignatureScheme>(
    zcap: &Delegation<(), CacaoZcapExtraProps>,
) -> Result<CACAO<S>, ZcapToCacaoError>
where
    S::Signature: TryFrom<Vec<u8>> + DagCbor,
{
    let Delegation {
        context: contexts,
        id,
        invoker: invoker_opt,
        property_set: zcap_extraprops,
        ..
    } = zcap;
    let CacaoZcapExtraProps {
        r#type: zcap_type,
        invocation_target,
        expires: expires_opt,
        valid_from: valid_from_opt,
        cacao_payload_type,
        cacao_zcap_substatement: cacao_zcap_substatement_opt,
        allowed_action: allowed_action_opt,
        cacao_request_id,
    } = zcap_extraprops;

    let stmt = CacaoZcapStatement::from_actions_and_substatement_opt(
        cacao_zcap_substatement_opt.as_ref().map(|s| s.as_str()),
        allowed_action_opt.as_ref(),
    );

    let proof = zcap.proof.as_ref().ok_or(ZcapToCacaoError::MissingProof)?;
    let proof_extraprops =
        CacaoZcapProofExtraProps::from_property_set_opt(proof.property_set.clone())
            .map_err(ZcapToCacaoError::ConvertProofExtraProps)?;
    let CacaoZcapProofExtraProps {
        capability_chain,
        cacao_signature_type,
    } = proof_extraprops;
    let Proof {
        type_: proof_type,
        proof_purpose,
        proof_value,
        verification_method: vm_opt,
        created: created_opt,
        nonce: nonce_opt,
        domain: domain_opt,
        ..
    } = proof;
    if zcap_type != DELEGATION_TYPE_2022 {
        return Err(ZcapToCacaoError::UnknownDelegationType);
    }
    if proof_type != PROOF_TYPE_2022 {
        return Err(ZcapToCacaoError::UnknownDelegationProofType);
    }
    let combined_type = format!("{}-{}", cacao_payload_type, cacao_signature_type);
    let s_id = S::id();
    if combined_type != s_id {
        return Err(ZcapToCacaoError::UnexpectedCACAOTypes {
            expected: s_id,
            found: combined_type,
        });
    }

    match contexts {
        Contexts::Many(contexts) => match contexts.as_slice() {
            [Context::URI(URI::String(c1)), Context::URI(URI::String(c2))]
                if c1 == SECURITY_V2_CONTEXT && c2 == CONTEXT_URL_V1 => {}
            _ => return Err(ZcapToCacaoError::BadContext),
        },
        Contexts::One(_) => return Err(ZcapToCacaoError::BadContext),
    };

    let invoker = invoker_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingInvoker)?
        .to_string();

    if proof_purpose.as_ref() != Some(&ProofPurpose::CapabilityDelegation) {
        return Err(ZcapToCacaoError::ExpectedCapabilityDelegationProofPurpose(
            proof_purpose.clone(),
        ));
    }

    let sig_mb = proof_value
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofValue)?;
    let (_base, sig) =
        multibase::decode(&sig_mb).map_err(ZcapToCacaoError::MultibaseDecodeProofValue)?;

    let domain = domain_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofDomain)?;
    let nonce = nonce_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofNonce)?;
    let created = created_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofCreated)?;
    let iat = TimeStamp::from(*created);
    let nbf_opt = match valid_from_opt {
        Some(valid_from) => Some(
            TimeStamp::from_str(valid_from)
                .map_err(ZcapToCacaoError::UnableToParseValidFromTimestamp)?,
        ),
        None => None,
    };
    let exp_opt = match expires_opt {
        Some(expires) => Some(
            TimeStamp::from_str(expires)
                .map_err(ZcapToCacaoError::UnableToParseExpiresTimestamp)?,
        ),
        None => None,
    };
    // First value of capability chain is the root capability; that is decoded to get the
    // invocation target which becomes the first value of the resources array.
    // Remaining values of the capability chain are delegation capability ids, that are passed
    // through into the resources array.
    let mut iter = capability_chain.into_iter();
    let (first_cap, last_cap, intermediate_caps) = (
        iter.next()
            .ok_or(ZcapToCacaoError::ExpectedNonEmptyCapabilityChain)?,
        iter.next_back(),
        iter,
    );

    let root_cap_urn =
        ZcapRootURN::from_str(first_cap.id()).map_err(ZcapToCacaoError::RootURIParse)?;
    let root_target = root_cap_urn.target;
    let last_cap_resources = match last_cap {
        None => vec![],
        Some(cap) => vec![Ok(cap
            .as_resource_uri()
            .map_err(ZcapToCacaoError::CapToResource)?)],
    };
    let resources =
        vec![Ok(root_target.clone())]
            .into_iter()
            .chain(intermediate_caps.map(|cap| {
                UriString::try_from(cap.id()).map_err(ZcapToCacaoError::ResourceURIParse)
            }))
            .chain(last_cap_resources.into_iter())
            .collect::<Result<Vec<UriString>, ZcapToCacaoError>>()?;

    if invocation_target != root_target.as_str() {
        return Err(ZcapToCacaoError::InvocationTargetInternalMismatch {
            invocation_target: invocation_target.to_string(),
            decoded_root_target: root_target,
        });
    }
    // TODO: check parentCapability is last value (converted if first value)

    // Infer issuer (verification method controller) from verification method URL.
    let vm = vm_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofVerificationMethod)?;
    let issuer = if vm.starts_with("did:pkh:") {
        if let Some(issuer) = vm.strip_suffix("#blockchainAccountId") {
            issuer
        } else {
            return Err(ZcapToCacaoError::UnknownPKHVerificationMethodURL);
        }
    } else {
        return Err(ZcapToCacaoError::UnknownVerificationMethodScheme);
    };

    let signature = S::Signature::try_from(sig).or(Err(ZcapToCacaoError::ConvertSignature))?;
    let payload = Payload {
        domain: domain.to_string().try_into().unwrap(),
        iss: issuer.try_into().map_err(ZcapToCacaoError::IssuerParse)?,
        statement: stmt.to_string_opt(),
        aud: invoker
            .as_str()
            .try_into()
            .map_err(ZcapToCacaoError::InvokerParseAud)?,
        version: CacaoVersion::V1,
        nonce: nonce.to_string(),
        iat,
        exp: exp_opt,
        nbf: nbf_opt,
        request_id: cacao_request_id.clone(),
        resources,
    };
    let cacao = payload.sign::<S>(signature);
    let URI::String(id_str) = id;
    let expected_uuid = cacao_cid_uuid(&cacao).to_string();
    if id_str.as_str() != expected_uuid {
        return Err(ZcapToCacaoError::UuidCidMismatch {
            found: id_str.to_string(),
            computed: expected_uuid,
        });
    }
    Ok(cacao)
}

/// Error [converting ZCAP to CACAO](zcap_to_cacao)
#[derive(Error, Debug)]
pub enum ZcapToCacaoError {
    /// Delegation object is missing a proof object
    #[error("Delegation object is missing a proof object")]
    MissingProof,

    /// Bad CACAO-ZCap Context
    ///
    /// CACAO-Zcap is expected to use specific context URIs:
    /// 1. [SECURITY_V2_CONTEXT]
    /// 2. [CONTEXT_URL_V1]
    #[error("Bad CACAO-ZCap Context")]
    BadContext,

    /// Delegation object is missing invoker property
    #[error("Delegation object is missing invoker property")]
    MissingInvoker,

    /// Proof object is missing signature (proofValue)
    #[error("Proof object is missing signature (proofValue)")]
    MissingProofValue,

    /// Unable to decode multibase proof value
    #[error("Unable to decode multbiase proof value")]
    MultibaseDecodeProofValue(#[source] multibase::Error),

    /// Unable to convert proof extra properties
    #[error("Unable to convert proof extra properties")]
    ConvertProofExtraProps(#[source] CacaoZcapProofConvertError),

    /// Unable to convert signature
    #[error("Unable to convert signature")]
    ConvertSignature,

    /// Missing verification method on proof object
    ///
    /// CACAO-Zcap proof object must have verificationMethod property.
    #[error("Missing verification method on proof object")]
    MissingProofVerificationMethod,

    /// Missing domain property of proof object
    ///
    /// CACAO-Zcap proof object must have domain property corresponding to CACAO domain value.
    #[error("Missing domain property of proof object")]
    MissingProofDomain,

    /// Missing nonce property of proof object
    ///
    /// CACAO-Zcap proof object must have nonce property corresponding to CACAO nonce value.
    #[error("Missing nonce property of proof object")]
    MissingProofNonce,

    /// Missing created property of proof object
    ///
    /// CACAO-Zcap proof object must have created property corresponding to CACAO created value.
    #[error("Missing created property of proof object")]
    MissingProofCreated,

    /// Unknown verification method scheme
    ///
    /// Expected "did:pkh:..."
    #[error("Unknown verification method scheme")]
    UnknownVerificationMethodScheme,

    /// Unknown PKH verification method URL
    ///
    /// Expected "did:pkh:...#blockchainAccountId"
    #[error("Unknown PKH verification method URL")]
    UnknownPKHVerificationMethodURL,

    /// Expected non-empty capabilityChain
    #[error("Expected non-empty capabilityChain")]
    ExpectedNonEmptyCapabilityChain,

    /// Unable to parse issuer URL
    #[error("Unable to parse issuer URL")]
    IssuerParse(#[source] iri_string::validate::Error),

    /// Unable to parse invoker URI as "aud" value
    #[error("Unable to parse invoker URI as \"aud\" value")]
    InvokerParseAud(#[source] iri_string::validate::Error),

    /// Unable to parse parse root capability URI
    ///
    /// Root capability URI (first value of
    /// [capabilityChain](CacaoZcapProofExtraProps::capability_chain) proof value)
    /// is expected to be a [ZcapRootURN].
    #[error("Unable to parse root capability URI")]
    RootURIParse(#[source] ZcapRootURNParseError),

    /// Invocation target did not match in delegation
    #[error("Invocation target did not match in delegation. Found invocationTarget value '{invocation_target}' and decoded root target URI '{decoded_root_target}'")]
    InvocationTargetInternalMismatch {
        /// [Invocation target](CacaoZcapExtraProps::invocation_target) from delegation object
        invocation_target: String,

        /// Target URL decoded from root capability URI (ZcapRootURN)
        decoded_root_target: UriString,
    },

    /// Unable to parse resource as URI
    #[error("Unable to parse resource as URI")]
    ResourceURIParse(#[source] iri_string::validate::Error),

    /// Unknown delegation type
    #[error("Unknown delegation type")]
    UnknownDelegationType,

    /// Unknown delegation proof type
    #[error("Unknown delegation proof type")]
    UnknownDelegationProofType,

    /// Unable to parse validFrom timestamp
    #[error("Unable to parse validFrom timestamp")]
    UnableToParseValidFromTimestamp(#[source] chrono::format::ParseError),

    /// Unable to parse expires timestamp
    #[error("Unable to parse expires timestamp")]
    UnableToParseExpiresTimestamp(#[source] chrono::format::ParseError),

    /// Expected capabilityDelegation proof purpose but found something else
    ///
    /// [CacaoZcapProof2022] can only be used with proof purpose [CapabilityDelegation](ProofPurpose::CapabilityDelegation)
    #[error("Expected capabilityDelegation proof purpose but found '{0:?}'")]
    ExpectedCapabilityDelegationProofPurpose(Option<ProofPurpose>),

    /// Unexpected CACAO types.
    #[error("Unexpected CACAO types. Expected '{expected}' but found '{found}'")]
    UnexpectedCACAOTypes {
        /// The id pair for the [SignatureScheme] generic argument to [zcap_to_cacao]
        expected: String,
        /// The id pair found in the ZCAP properties ([CacaoZcapProofExtraProps::cacao_signature_type and [CacaoZcapExtraProps::cacao_payload_type])
        found: String,
    },

    /// Unable to convert capability chain item to resource URI
    #[error("Unable to convert capability chain item to resource URI")]
    CapToResource(#[source] CapToResourceError),

    /// UUID CID mismatch
    #[error("UUID CID mismatch. Computed: '{computed}' but found: '{found}'")]
    UuidCidMismatch {
        /// Computed this UUID-CID
        computed: String,

        /// Found this id in the delegation id
        found: String,
    },
}
