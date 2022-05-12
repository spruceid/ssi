use std::str::FromStr;

use cacaos::{Header, Payload, SignatureScheme, Version as CacaoVersion, CACAO};
use chrono::DateTime;
use iri_string::types::UriString;
use libipld::cbor::DagCbor;
use ssi::{
    jsonld::SECURITY_V2_CONTEXT,
    one_or_many::OneOrMany,
    vc::{Proof, ProofPurpose, URI},
    zcap::{Context, Contexts, Delegation},
};
use thiserror::Error;

use crate::{
    cacao_cid_uuid, CacaoZcapExtraProps, CacaoZcapProofConvertError, CacaoZcapProofExtraProps,
    CacaoZcapStatement, CapFromResourceError, CapabilityChainItem, ZcapRootURN, CONTEXT_URL_V1,
    DELEGATION_TYPE_2022, PROOF_TYPE_2022,
};

/// Convert a CACAO to a Zcap (delegation)
pub fn cacao_to_zcap<S: SignatureScheme>(
    cacao: &CACAO<S>,
) -> Result<Delegation<(), CacaoZcapExtraProps>, CacaoToZcapError>
where
    S::Signature: AsRef<[u8]> + DagCbor,
{
    let header = cacao.header();
    let Payload {
        domain,
        iss: issuer,
        statement: statement_opt,
        aud,
        version,
        nonce,
        iat,
        exp: exp_opt,
        nbf: nbf_opt,
        request_id: request_id_opt,
        resources,
    } = cacao.payload();
    match version {
        CacaoVersion::V1 => {}
        #[allow(unreachable_patterns)]
        _ => return Err(CacaoToZcapError::UnknownCacaoVersion),
    }
    let signature = cacao.signature();

    let (substatement_opt, allowed_action_opt) = if let Some(statement) = statement_opt {
        let cacao_zcap_stmt =
            CacaoZcapStatement::from_str(statement).map_err(CacaoToZcapError::StatementParse)?;
        (cacao_zcap_stmt.substatement, cacao_zcap_stmt.actions)
    } else {
        (None, None)
    };

    let valid_from_opt = nbf_opt.as_ref().map(|nbf| nbf.to_string());
    let exp_string_opt = exp_opt.as_ref().map(|ts| ts.to_string());

    let (header_type, signature_type) = get_header_and_signature_type(header)?;
    let uuid = cacao_cid_uuid(cacao);
    let id = URI::String(uuid.to_string());
    let mut iter = resources.iter();
    let (first_resource, last_resource, intermediate_resources) = (
        iter.next().ok_or(CacaoToZcapError::MissingFirstResource)?,
        iter.next_back(),
        iter,
    );

    let invocation_target = first_resource;
    let root_cap_urn = ZcapRootURN {
        target: first_resource.clone(),
    };
    let root_cap_urn_string = root_cap_urn.to_string();
    let root_cap_urn_uri = UriString::try_from(root_cap_urn_string.as_str())
        .map_err(CacaoToZcapError::RootCapUriParse)?;
    let previous_caps = match last_resource {
        None => vec![],
        Some(resource) => vec![CapabilityChainItem::from_resource_uri(resource)
            .map_err(CacaoToZcapError::CapFromResource)?],
    };
    let capability_chain: Vec<CapabilityChainItem> =
        vec![CapabilityChainItem::Id(root_cap_urn_uri)]
            .into_iter()
            .chain(intermediate_resources.cloned().map(CapabilityChainItem::Id))
            .chain(previous_caps.into_iter())
            .collect();
    let parent_capability_id = capability_chain
        .iter()
        .next_back()
        // capability_chain has at least one value, but using unwrap_or here anyway
        .map(|cap| cap.id())
        .unwrap_or(&root_cap_urn_string)
        .to_string();

    let invoker_uri = URI::String(aud.as_str().to_string());
    let created_datetime = DateTime::parse_from_rfc3339(&iat.to_string())
        .map_err(CacaoToZcapError::ParseIssuedAtDate)?
        .into();

    let vm_string = if let Some(pkh) = issuer.as_str().strip_prefix("did:pkh:") {
        format!("did:pkh:{}#blockchainAccountId", pkh)
    } else {
        return Err(CacaoToZcapError::UnknownIssuerScheme);
    };
    let proof_value_string = multibase::encode(multibase::Base::Base16Lower, signature);
    let proof_extraprops = CacaoZcapProofExtraProps {
        capability_chain,
        cacao_signature_type: signature_type,
    }
    .into_property_set_opt()
    .map_err(CacaoToZcapError::ConvertProofExtraProps)?;
    let proof = Proof {
        proof_purpose: Some(ProofPurpose::CapabilityDelegation),
        proof_value: Some(proof_value_string),
        verification_method: Some(vm_string),
        domain: Some(domain.to_string()),
        nonce: Some(nonce.to_string()),
        property_set: proof_extraprops,
        created: Some(created_datetime),
        ..Proof::new(PROOF_TYPE_2022)
    };
    let delegation_extraprops = CacaoZcapExtraProps {
        r#type: String::from(DELEGATION_TYPE_2022),
        expires: exp_string_opt,
        valid_from: valid_from_opt,
        invocation_target: invocation_target.to_string(),
        cacao_payload_type: header_type,
        allowed_action: allowed_action_opt,
        cacao_zcap_substatement: substatement_opt,
        cacao_request_id: request_id_opt.clone(),
    };
    let mut delegation = Delegation {
        context: Contexts::Many(vec![
            Context::URI(URI::String(SECURITY_V2_CONTEXT.into())),
            Context::URI(URI::String(CONTEXT_URL_V1.into())),
        ]),
        invoker: Some(invoker_uri),
        ..Delegation::new(id, URI::String(parent_capability_id), delegation_extraprops)
    };
    delegation.proof = Some(proof);
    Ok(delegation)
}

/// Error [converting CACAO to a Zcap](cacao_to_zcap)
#[derive(Error, Debug)]
pub enum CacaoToZcapError {
    /// Unknown CACAO version. Expected v1.
    #[error("Unknown CACAO version")]
    UnknownCacaoVersion,

    /// Unable to parse issuedAt (iat) date
    #[error("Unable to parse issuedAt (iat) date")]
    ParseIssuedAtDate(#[source] chrono::format::ParseError),

    /// Unable to parse expiration (exp) date
    #[error("Unable to parse expiration (exp) date")]
    ParseExpDate(#[source] chrono::format::ParseError),

    /// Unknown issuer scheme. Expected PKH DID (did:pkh:).
    #[error("Unknown issuer scheme")]
    UnknownIssuerScheme,

    /// Unable to parse CACAO combined type.
    ///
    /// Expected e.g. "eip4361-eip191"
    #[error("Unable to parse CACAO type")]
    CombinedTypeParse,

    /// Unable to convert CACAO proof extra properties
    #[error("Unable to convert CACAO proof extra properties")]
    ConvertProofExtraProps(#[source] CacaoZcapProofConvertError),

    /// Missing first resource
    ///
    /// CACAO-zcap must have at least one resource URI.
    /// The first resource URI is the invocation target.
    #[error("Missing first resource")]
    MissingFirstResource,

    /// Missing last resource
    ///
    /// CACAO-zcap must have last resource URI for the embedded previous delegation, unless
    /// previous delegation is the root/target zcap.
    #[error("Missing last resource")]
    MissingLastResource,

    /// Unable to convert resource URI to capability chain item
    #[error("Unable to convert resource URI to capability chain item")]
    CapFromResource(#[source] CapFromResourceError),

    /// Unable to parse root capability id as URI
    #[error("Unable to parse root capability id as URI")]
    RootCapUriParse(#[source] iri_string::validate::Error),

    /// Unable to parse CACAO-ZCAP statement string
    #[error("Unable to parse CACAO-ZCAP statement string")]
    StatementParse(#[source] CacaoZcapStatementParseError),
}

/// Error [parsing CacaoZcapStatement](CacaoZcapStatement::from_str)
#[derive(Error, Debug)]
pub enum CacaoZcapStatementParseError {
    /// Unexpected statement prefix
    #[error("Unexpected statement prefix")]
    UnexpectedPrefix,

    /// Expected separator
    #[error("Expected separator before substatement")]
    ExpectedSeparatorBeforeSubstatement,

    /// Expected separator after actions
    #[error("Expected separator after actions")]
    ExpectedSeparatorAfterActions,
}

impl FromStr for CacaoZcapStatement {
    type Err = CacaoZcapStatementParseError;
    fn from_str(stmt: &str) -> Result<Self, Self::Err> {
        let mut s = stmt
            .strip_prefix("Authorize action")
            .ok_or(CacaoZcapStatementParseError::UnexpectedPrefix)?;

        let actions = if let Some(after_paren) = s.strip_prefix(" (") {
            let (actions_to_split, after_actions) = after_paren
                .split_once(')')
                .ok_or(CacaoZcapStatementParseError::ExpectedSeparatorAfterActions)?;
            s = after_actions;
            Some(OneOrMany::Many(
                actions_to_split
                    .split(", ")
                    .map(String::from)
                    .collect::<Vec<String>>(),
            ))
        } else {
            None
        };
        let substatement = if s.is_empty() {
            None
        } else {
            Some(
                s.strip_prefix(": ")
                    .ok_or(CacaoZcapStatementParseError::ExpectedSeparatorBeforeSubstatement)?
                    .to_string(),
            )
        };
        Ok(Self {
            actions,
            substatement,
        })
    }
}

fn get_header_and_signature_type(header: &Header) -> Result<(String, String), CacaoToZcapError> {
    let combined_type = header.t();
    match combined_type
        .splitn(2, '-')
        .collect::<Vec<&str>>()
        .as_slice()
    {
        [t1, t2] => Ok((t1.to_string(), t2.to_string())),
        _ => Err(CacaoToZcapError::CombinedTypeParse),
    }
}
