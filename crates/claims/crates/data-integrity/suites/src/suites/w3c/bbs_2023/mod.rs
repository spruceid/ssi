//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    hash::Hash,
    ops::Deref,
};

use getrandom::getrandom;
use hmac::{digest::KeyInit, Hmac};
use iref::IriBuf;
use ssi_json_ld::{
    context_processing::ProcessedOwned, syntax::Value, Compact, JsonLdProcessor, Process, Profile,
    RemoteDocument,
};
use k256::sha2::{Digest, Sha256};
use linked_data::IntoQuadsError;
use rdf_types::{
    generator,
    vocabulary::{ExtractFromVocabulary, IriVocabulary, IriVocabularyMut},
    BlankId, BlankIdBuf, Id, LexicalQuad, Term, Vocabulary, VocabularyMut,
};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    suite::{
        standard::{
            HashingAlgorithm, HashingError, SignatureAlgorithm, SignatureAndVerificationAlgorithm,
            TransformationAlgorithm, TransformationError, TransformedData,
            TypedTransformationAlgorithm, VerificationAlgorithm,
        },
        ConfigurationAlgorithm, ConfigurationError, InputProofOptions,
    },
    ProofConfiguration, ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_json_ld::{JsonLdObject, Expandable};
use ssi_rdf::LdEnvironment;
use ssi_verification_methods::Multikey;

mod json_pointer;
pub use json_pointer::*;

mod transformation;
use transformation::TransformedDerived;
pub use transformation::{Bbs2023Transformation, Bbs2023TransformationOptions, Transformed};

mod hashing;
use hashing::BaseHashData;
pub use hashing::{Bbs2023Hashing, HashData};

mod signature;
pub use signature::Bbs2023SignatureAlgorithm;

mod verification;

/// The `bbs-2023` cryptographic suite.
#[derive(Debug, Clone, Copy)]
pub struct Bbs2023;

impl StandardCryptographicSuite for Bbs2023 {
    type Configuration = Bbs2023Configuration;

    type Transformation = Bbs2023Transformation;

    type Hashing = Bbs2023Hashing;

    type VerificationMethod = Multikey;

    type ProofOptions = Bbs2023Options;

    type SignatureAlgorithm = Bbs2023SignatureAlgorithm;

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof("bbs-2023")
    }
}

pub struct Bbs2023InputOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub feature_option: FeatureOption,

    pub commitment_with_proof: Option<Vec<u8>>,

    pub proof_options: Bbs2023Options,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum FeatureOption {
    #[default]
    Baseline,
    AnonymousHolderBinding,
    PseudonymIssuerPid,
    PseudonymHiddenPid,
}

/// Base Proof Configuration.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023>
pub struct Bbs2023Configuration;

impl ConfigurationAlgorithm<Bbs2023> for Bbs2023Configuration {
    /// Input type for the verification method.
    type InputVerificationMethod = Multikey;

    /// Input suite-specific proof options.
    type InputProofOptions = ();

    /// Input signature options.
    type InputSignatureOptions = Bbs2023InputOptions;

    /// Document transformation options.
    type TransformationOptions = Bbs2023TransformationOptions;

    fn configure(
        _: &Bbs2023,
        options: InputProofOptions<Bbs2023>,
        signature_options: Bbs2023InputOptions,
    ) -> Result<(ProofConfiguration<Bbs2023>, Bbs2023TransformationOptions), ConfigurationError>
    {
        todo!()
    }
}

#[derive(Serialize)]
pub struct Bbs2023Options;

#[derive(Serialize)]
pub struct Bbs2023Signature;

impl AsRef<str> for Bbs2023Signature {
    fn as_ref(&self) -> &str {
        todo!()
    }
}
