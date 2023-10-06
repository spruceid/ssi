use ssi_dids::{
    document::representation,
    json_ld::{
        syntax::context::{
            term_definition::{Expanded, Id, Type, TypeKeyword},
            TermDefinition,
        },
        Entry, Nullable,
    },
};
use static_iref::iri;

use crate::{PkhVerificationMethod, PkhVerificationMethodType};

#[derive(Debug, Default)]
pub struct JsonLdContext {
    ed25519_verification_key_2018: bool,
    ecdsa_secp256k1_recovery_method_2020: bool,
    tezos_method_2021: bool,
    solana_method_2021: bool,
    blockchain_verification_method_2021: bool,
    ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    p256_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    blockchain_account_id: bool,
    public_key_jwk: bool,
}

impl JsonLdContext {
    pub fn add_verification_method(&mut self, m: &PkhVerificationMethod) {
        // self.blockchain_account_id |= m.blockchain_account_id.is_some();
        self.blockchain_account_id = true;
        self.public_key_jwk |= m.public_key_jwk.is_some();
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

impl From<JsonLdContext> for representation::json_ld::ContextEntry {
    fn from(value: JsonLdContext) -> Self {
        use representation::json_ld::context::Definition;
        let mut def = Definition::new();

        if value.ed25519_verification_key_2018 {
            let ty = PkhVerificationMethodType::Ed25519VerificationKey2018;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.ecdsa_secp256k1_recovery_method_2020 {
            let ty = PkhVerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                PkhVerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                PkhVerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.tezos_method_2021 {
            let ty = PkhVerificationMethodType::TezosMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.solana_method_2021 {
            let ty = PkhVerificationMethodType::SolanaMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.blockchain_account_id {
            let ty = PkhVerificationMethodType::BlockchainVerificationMethod2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.blockchain_account_id {
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

        if value.public_key_jwk {
            def.bindings.insert(
                "publicKeyJwk".into(),
                Nullable::Some(TermDefinition::Expanded(Box::new(Expanded {
                    id: Some(Entry::new(Nullable::Some(Id::Term(
                        iri!("https://w3id.org/security#publicKeyJwk")
                            .to_owned()
                            .into_string(),
                    )))),
                    type_: Some(Entry::new(Nullable::Some(Type::Keyword(TypeKeyword::Json)))),
                    ..Default::default()
                }))),
            );
        }

        Self::Definition(def)
    }
}
