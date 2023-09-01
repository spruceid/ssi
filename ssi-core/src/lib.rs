use async_trait::async_trait;
pub mod futures;
pub mod one_or_many;
pub mod uri;

// one type of VM (e.g. a JWK) should be able to verify multiple types of things (payloads)
// in multiple ways/contexts (context properties), so generic over those. but each impl should
// have one concrete err type, so associated
#[async_trait]
pub trait VerificationMethod<SP, C> {
    type Error;
    async fn verify(&self, signed_payload: SP, context_properties: C) -> Result<(), Self::Error>;
}

// can return an attached or detached signature
#[async_trait]
pub trait SigningMethod<P, C, O> {
    type Error;
    async fn sign(&self, payload: P, context_properties: C) -> Result<O, Self::Error>;
}

#[async_trait]
pub trait ProofConstruction<P, C, I, O, S> {
    type Error;
    async fn prepare(payload: P, context_properties: C) -> Result<I, Self::Error>;
    fn complete(payload: P, context_properties: C, proof: S) -> Result<O, Self::Error>;
}

#[async_trait]
pub trait Verifiable<V, C> {
    type Error;
    async fn verify_with(&self, vm: V, c: C) -> Result<(), Self::Error>;
}

pub trait Authenticated {
    type Id;
    fn authenticator(&self) -> Self::Id;
}

#[async_trait]
pub trait VerificationMethodRegistry<I> {
    type Error;
    type VM;
    async fn get_method(&self, id: I) -> Result<Option<Self::VM>, Self::Error>;
}

pub enum VDRError<R, V> {
    Registry(R),
    IdUnresolvable,
    Verification(V),
}

pub trait SemanticallyVerifiable<P> {
    type Error;
    fn verify_claims(&self, policy: P) -> Result<(), Self::Error>;
}

pub trait ChronologicallyVerifiable<T> {
    fn valid_now(&self) -> bool;
    fn valid_at(&self, time: T) -> bool;
}
