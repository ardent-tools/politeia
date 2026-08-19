//! politeia-evidence: evidence, verification, and attestation records.
//!
//! Evidence carries claims; attestation binds a verified subject to the exact
//! policy, runtime, adapter, and delegation identities it was verified under.

#![deny(missing_docs)]

use politeia_core::{
    AdapterId, DelegationId, Digest, EvidenceId, PolicyBundleId, PrincipalId, RuntimeGenerationId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How independent the evidence producer is from the actor being judged.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum IndependenceClass {
    /// The actor reports on itself (weakest; never satisfies an
    /// independent-verification obligation).
    SelfReported,
    /// Same actor, separate process.
    SameActorDifferentProcess,
    /// A different agent produced the evidence.
    IndependentAgent,
    /// A separate service produced the evidence.
    IndependentService,
    /// A human authority produced or approved the evidence.
    HumanAuthority,
}

/// A provenance-bearing evidence record admitted for a claim.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceRecord {
    /// This record's identity.
    pub id: EvidenceId,
    /// Digest of the exact subject the evidence is about.
    pub subject: Digest,
    /// The principal that produced the evidence.
    pub producer: PrincipalId,
    /// The collection method (how the evidence was produced).
    pub method: String,
    /// Digest of the evidence payload.
    pub payload_digest: Digest,
    /// The producer's independence from the actor being judged.
    pub independence: IndependenceClass,
}

/// An independent or designated evaluation of evidence against a subject.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Verification {
    /// Digest of the verified subject.
    pub subject: Digest,
    /// The verifying principal.
    pub verifier: PrincipalId,
    /// The evidence records the verdict relies on.
    pub evidence: Vec<EvidenceId>,
    /// Whether the subject passed.
    pub passed: bool,
    /// The verifier's independence class.
    pub independence: IndependenceClass,
}

/// A durable statement binding a verified subject to the exact policy,
/// runtime, adapter, delegation, and evidence identities it was verified
/// under. An attestation is not portable to another subject.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Attestation {
    /// Digest of the attested subject.
    pub subject: Digest,
    /// The attesting verifier.
    pub verifier: PrincipalId,
    /// The policy bundle identity.
    pub policy: PolicyBundleId,
    /// The runtime generation identity.
    pub runtime: RuntimeGenerationId,
    /// The adapter identity.
    pub adapter: AdapterId,
    /// The delegation identity the work ran under.
    pub delegation: DelegationId,
    /// The evidence records bound into the attestation.
    pub evidence: Vec<EvidenceId>,
    /// Digest of the full attestation statement.
    pub statement_digest: Digest,
}
