//! politeia-policy: normative clauses, detector specs, bindings, decisions.
//!
//! A clause is the normative proposition; a detector is an evidence-producing
//! mechanism with declared blind spots; a binding applies a clause to a scope
//! with a consequence. None of the three is interchangeable with another.

#![deny(missing_docs)]

pub mod bootstrap;
pub mod evaluate;
pub mod hardening;
pub mod waiver;

use std::collections::BTreeSet;

use jiff::Timestamp;
use politeia_core::{Digest, EvidenceId, PolicyBundleId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use hardening::BindingAuthority;

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
    /// Exact control version expected in a run and activation proof.
    pub control_version: String,
    /// Digest of the exact control configuration.
    pub configuration_digest: Digest,
    /// Mediation path on which the control must run.
    pub mediation_path: String,
    /// Scopes this control is designed to observe.
    pub supported_scopes: BTreeSet<String>,
    /// Digest of the adversarial population used to calibrate this control.
    pub calibration_population: Digest,
    /// Its known blind spots.
    pub known_blind_spots: Vec<String>,
}

/// The consequence a binding applies when its clause is evaluated, from
/// weakest to strongest.
///
/// WHY the ordering is derived rather than written out: declaration order *is*
/// the severity order, and [`hardening::HardeningState::authorises`] compares
/// with `<=` against the strongest consequence a rung permits. A second,
/// hand-kept severity table would be the same fact in two places, free to
/// disagree. `hardening`'s tests assert the order so a reordering cannot
/// silently redefine what every rung permits.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// The rung this binding has climbed to, and the consequence that rung
    /// authorises it to apply.
    ///
    /// The two travel together because neither is meaningful alone: a
    /// consequence without the climb behind it is an assertion of authority the
    /// binding has not earned, and [`BindingAuthority`] is what makes that pair
    /// unrepresentable rather than merely discouraged.
    pub authority: BindingAuthority,
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
    /// Digest of the exact subject the controls judged.
    pub subject: Digest,
    /// Digest of the exact population whose coverage was evaluated.
    pub population: Digest,
    /// The principal the decision is for.
    pub principal: PrincipalId,
    /// Whether the operation is allowed.
    pub allowed: bool,
    /// The bindings that contributed to the decision.
    pub binding_ids: Vec<String>,
    /// Exact admitted control runs that contributed.
    pub control_runs: Vec<EvidenceId>,
    /// Exact admitted activation proofs used for blocking authority.
    pub activation_proofs: Vec<EvidenceId>,
    /// Exact delegated waivers that excused findings.
    pub waiver_ids: Vec<String>,
    /// Human-readable reasons.
    pub reasons: Vec<String>,
}

/// An authorized, scoped, expiring exception to a binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// Waiver identity.
    pub id: String,
    /// The binding being waived.
    pub binding_id: String,
    /// Exact policy bundle containing the binding.
    pub policy: PolicyBundleId,
    /// Digest of the exact policy bytes containing the binding.
    pub policy_digest: Digest,
    /// Digest of the exact subject for which the exception was granted.
    pub subject: Digest,
    /// Digest of the exact population for which the exception was granted.
    pub population: Digest,
    /// The scope the waiver covers.
    pub scope: String,
    /// Why the waiver was granted.
    pub reason: String,
    /// Expiry instant; the waiver fails closed at and after it.
    pub expires_at: Timestamp,
}
