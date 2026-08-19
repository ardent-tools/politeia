use politeia_core::{AdapterId, DelegationId, Digest, EvidenceId, PolicyBundleId, PrincipalId, RuntimeGenerationId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum IndependenceClass {
    SelfReported,
    SameActorDifferentProcess,
    IndependentAgent,
    IndependentService,
    HumanAuthority,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub subject: Digest,
    pub producer: PrincipalId,
    pub method: String,
    pub payload_digest: Digest,
    pub independence: IndependenceClass,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Verification {
    pub subject: Digest,
    pub verifier: PrincipalId,
    pub evidence: Vec<EvidenceId>,
    pub passed: bool,
    pub independence: IndependenceClass,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Attestation {
    pub subject: Digest,
    pub verifier: PrincipalId,
    pub policy: PolicyBundleId,
    pub runtime: RuntimeGenerationId,
    pub adapter: AdapterId,
    pub delegation: DelegationId,
    pub evidence: Vec<EvidenceId>,
    pub statement_digest: Digest,
}
