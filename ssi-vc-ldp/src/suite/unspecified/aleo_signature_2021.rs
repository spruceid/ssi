/// Aleo Signature 2021
///
/// Linked data signature suite using [Aleo](crate::aleo).
///
/// # Transformation algorithm
/// 
/// This suite accepts linked data documents transformed into a canonical
/// RDF graph using the [URDNA2015][1] algorithm.
/// 
/// [1]: <https://w3id.org/security#URDNA2015>
/// 
/// # Hashing algorithm
/// 
/// The SHA-256 algorithm is used to hash the input canonical RDF graph and the
/// proof configuration graph, also in canonical form. Both hashes are then
/// concatenated into a single 64-bytes message, ready to be signed.
///
/// # Verification method
///
/// The following verification methods my be used to sign/verify a credential
/// with this suite:
/// - [`AleoMethod2021`]
/// - [`BlockchainVerificationMethod2021`]
pub struct AleoSignature2021;