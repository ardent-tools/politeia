use politeia_core::{PolicyBundleId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum ClauseKind {
    Invariant,
    Precondition,
    Postcondition,
    Obligation,
    Prohibition,
    Permission,
    Preference,
    Heuristic,
    Doctrine,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct NormativeClause {
    pub id: String,
    pub kind: ClauseKind,
    pub statement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum EvidenceClass {
    Substance,
    StructuralProxy,
    LexicalProxy,
    Heuristic,
    FormalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DetectorSpec {
    pub id: String,
    pub evidence_class: EvidenceClass,
    pub known_blind_spots: Vec<String>,
    pub calibrated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Consequence {
    Informational,
    Advisory,
    RequireReview,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PolicyBinding {
    pub id: String,
    pub clause_id: String,
    pub detector_ids: Vec<String>,
    pub scope: String,
    pub consequence: Consequence,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PolicyDecision {
    pub bundle: PolicyBundleId,
    pub principal: PrincipalId,
    pub allowed: bool,
    pub binding_ids: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Waiver {
    pub id: String,
    pub binding_id: String,
    pub scope: String,
    pub reason: String,
    pub issuer: PrincipalId,
    pub expires_at_rfc3339: String,
}
