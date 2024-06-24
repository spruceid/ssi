use iref::Iri;
use ssi_dids_core::{
    document::representation,
    ssi_json_ld::{
        syntax::context::{
            term_definition::{Expanded, Id, Type, TypeKeyword},
            TermDefinition,
        },
        Nullable,
    },
};
use static_iref::iri;

use crate::{PkhVerificationMethod, PkhVerificationMethodType, PublicKey};

const BLOCKCHAIN2021_V1_CONTEXT: &Iri = iri!("https://w3id.org/security/suites/blockchain-2021/v1");

#[derive(Debug, Default)]
pub struct JsonLdContext {
    /// `https://w3id.org/security/suites/blockchain-2021/v1` context.
    blockchain_2021_v1: bool,
    ed25519_verification_key_2018: bool,
    ecdsa_secp256k1_recovery_method_2020: bool,
    tezos_method_2021: bool,
    solana_method_2021: bool,
    blockchain_verification_method_2021: bool,
    ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    p256_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    blockchain_account_id: bool,
    public_key_jwk: bool,
    public_key_base58: bool,
}

impl JsonLdContext {
    pub fn add_blockchain_2021_v1(&mut self) {
        self.blockchain_2021_v1 = true
    }

    pub fn add_verification_method(&mut self, m: &PkhVerificationMethod) {
        // self.blockchain_account_id |= m.blockchain_account_id.is_some();
        self.blockchain_account_id = true;

        match &m.public_key {
            Some(PublicKey::Jwk(_)) => self.public_key_jwk |= true,
            Some(PublicKey::Base58(_)) => self.public_key_base58 |= true,
            None => (),
        }

        self.add_verification_method_type(m.type_);
    }

    pub fn add_verification_method_type(&mut self, ty: PkhVerificationMethodType) {
        match ty {
            PkhVerificationMethodType::BlockchainVerificationMethod2021 => {
                self.blockchain_verification_method_2021 = true
            }
            PkhVerificationMethodType::SolanaMethod2021 => {
                self.solana_method_2021 = true
            }
            PkhVerificationMethodType::TezosMethod2021 => {
                self.tezos_method_2021 = true
            }
            PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020 => {
                self.ecdsa_secp256k1_recovery_method_2020 = true
            }
            PkhVerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
            PkhVerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
            PkhVerificationMethodType::Ed25519VerificationKey2018 => {
                self.ed25519_verification_key_2018 = true
            }
        }
    }
}

impl JsonLdContext {
    pub fn into_entries(self) -> Vec<representation::json_ld::ContextEntry> {
        use representation::json_ld::context::Definition;
        let mut def = Definition::new();

        if self.ed25519_verification_key_2018 {
            let ty = PkhVerificationMethodType::Ed25519VerificationKey2018;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.ecdsa_secp256k1_recovery_method_2020 {
            let ty = PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                PkhVerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                PkhVerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.tezos_method_2021 {
            let ty = PkhVerificationMethodType::TezosMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.solana_method_2021 {
            let ty = PkhVerificationMethodType::SolanaMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.blockchain_verification_method_2021 && !self.blockchain_2021_v1 {
            let ty = PkhVerificationMethodType::BlockchainVerificationMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if self.blockchain_account_id && !self.blockchain_2021_v1 {
            def.bindings.insert(
                "blockchainAccountId".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#blockchainAccountId")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        if self.public_key_jwk {
            def.bindings.insert(
                "publicKeyJwk".into(),
                Nullable::Some(TermDefinition::Expanded(Box::new(Expanded {
                    id: Some(Nullable::Some(Id::Term(
                        iri!("https://w3id.org/security#publicKeyJwk")
                            .to_owned()
                            .into_string(),
                    ))),
                    type_: Some(Nullable::Some(Type::Keyword(TypeKeyword::Json))),
                    ..Default::default()
                }))),
            );
        }

        if self.public_key_base58 {
            def.bindings.insert(
                "publicKeyBase58".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyBase58")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        let mut entries = Vec::new();

        if self.blockchain_2021_v1 {
            entries.push(representation::json_ld::ContextEntry::IriRef(
                BLOCKCHAIN2021_V1_CONTEXT.to_owned().into(),
            ))
        }

        if !def.bindings.is_empty() {
            entries.push(representation::json_ld::ContextEntry::Definition(def))
        }

        entries
    }
}
