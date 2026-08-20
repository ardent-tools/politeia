//! politeia-policy: normative clauses, detector specs, bindings, decisions.
//!
//! A clause is the normative proposition; a detector is an evidence-producing
//! mechanism with declared blind spots; a binding applies a clause to a scope
//! with a consequence. None of the three is interchangeable with another.

#![deny(missing_docs)]

use politeia_core::{Digest, PolicyBundleId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The kind of a normative clause.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum ClauseKind {
    /// Must always hold.
    Invariant,
    /// Must hold before.
    Precondition,
    /// Must hold after.
    Postcondition,
    /// Required action or evidence.
    Obligation,
    /// Must never hold.
    Prohibition,
    /// May hold.
    Permission,
    /// Defeasible choice among valid alternatives.
    Preference,
    /// A fallible proxy, honest about being one.
    Heuristic,
    /// Human doctrine; guidance without a mechanism.
    Doctrine,
}

/// A proposition about what must, may, or must not be true.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NormativeClause {
    /// Clause identity.
    pub id: String,
    /// The clause kind.
    pub kind: ClauseKind,
    /// The proposition statement.
    pub statement: String,
}

/// The evidence class a detector produces, from strongest to weakest.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum EvidenceClass {
    /// The property itself, demonstrated.
    Substance,
    /// A structural proxy for the property.
    StructuralProxy,
    /// A lexical proxy for the property.
    LexicalProxy,
    /// A heuristic signal.
    Heuristic,
    /// A formal proof.
    FormalProof,
}

/// An evidence-producing mechanism with declared assurance metadata. A
/// detector is not the normative claim and carries no blocking authority of
/// its own.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectorSpec {
    /// Detector identity.
    pub id: String,
    /// The evidence class it produces.
    pub evidence_class: EvidenceClass,
    /// Its known blind spots.
    pub known_blind_spots: Vec<String>,
    /// Whether it has been calibrated against adversarial fixtures.
    pub calibrated: bool,
}

/// The consequence a binding applies when its clause is evaluated.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Consequence {
    /// Record only.
    Informational,
    /// Surface as advice.
    Advisory,
    /// Require human review before proceeding.
    RequireReview,
    /// Deny.
    Deny,
}

/// Where a clause applies, which detectors produce admissible evidence, and
/// what consequence follows.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    /// Binding identity.
    pub id: String,
    /// The clause it applies.
    pub clause_id: String,
    /// The detectors whose evidence is admissible.
    pub detector_ids: Vec<String>,
    /// The scope the binding applies to.
    pub scope: String,
    /// The consequence on evaluation.
    pub consequence: Consequence,
}

/// A normalized authorization/governance result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    /// The policy bundle the decision was made under.
    pub bundle: PolicyBundleId,
    /// Digest of the exact policy bundle bytes used for the decision.
    pub policy_digest: Digest,
    /// Digest of the exact normalized operation intent that was decided.
    pub intent_digest: Digest,
    /// The principal the decision is for.
    pub principal: PrincipalId,
    /// Whether the operation is allowed.
    pub allowed: bool,
    /// The bindings that contributed to the decision.
    pub binding_ids: Vec<String>,
    /// Human-readable reasons.
    pub reasons: Vec<String>,
}

/// An authorized, scoped, expiring exception to a binding.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// Waiver identity.
    pub id: String,
    /// The binding being waived.
    pub binding_id: String,
    /// The scope the waiver covers.
    pub scope: String,
    /// Why the waiver was granted.
    pub reason: String,
    /// The principal that granted it.
    pub issuer: PrincipalId,
    /// Expiry time (RFC 3339).
    pub expires_at_rfc3339: String,
}
