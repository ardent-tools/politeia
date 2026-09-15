//! politeia-policy: normative clauses, detector specs, bindings, decisions.
//!
//! A clause is the normative proposition; a detector is an evidence-producing
//! mechanism with declared blind spots; a binding applies a clause to a scope
//! with a consequence. None of the three is interchangeable with another.

#![deny(missing_docs)]

pub mod bootstrap;
pub mod evaluate;
pub mod hardening;
pub mod operational;
pub mod waiver;

use std::collections::BTreeSet;

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{Digest, EvidenceId, PolicyBundleId, PrincipalId, RuntimeGenerationId};
use politeia_evidence::assurance::ControlRun;
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

impl PolicyBinding {
    /// Whether this binding's authoritative consequence can stop an operation.
    pub fn is_blocking(&self) -> bool {
        self.authority.consequence() >= Consequence::RequireReview
    }
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
    /// In-process provenance established only by an admitted policy path.
    ///
    /// This is deliberately absent from the policy-decision wire contract. A
    /// received or restored decision therefore has no dispatch authority and
    /// must be evaluated again. The dispatcher separately binds an admitted
    /// purpose into its lease and reservation claims.
    #[serde(skip)]
    #[schemars(skip)]
    purpose: Option<DecisionPurpose>,
}

impl PolicyDecision {
    /// Construct an ordinary in-process decision from a trusted policy point.
    ///
    /// This preserves the established decision wire shape while ensuring a
    /// deserialized decision cannot silently recover dispatch authority.
    #[expect(
        clippy::too_many_arguments,
        reason = "a normalized decision binds each independent evaluation axis"
    )]
    pub(crate) fn operational(
        bundle: PolicyBundleId,
        policy_digest: Digest,
        intent_digest: Digest,
        subject: Digest,
        population: Digest,
        principal: PrincipalId,
        allowed: bool,
        binding_ids: Vec<String>,
        control_runs: Vec<EvidenceId>,
        activation_proofs: Vec<EvidenceId>,
        waiver_ids: Vec<String>,
        reasons: Vec<String>,
    ) -> Result<Self, CanonicalError> {
        Self {
            bundle,
            policy_digest,
            intent_digest,
            subject,
            population,
            principal,
            allowed,
            binding_ids,
            control_runs,
            activation_proofs,
            waiver_ids,
            reasons,
            purpose: None,
        }
        .seal(DecisionPurposeKind::Operational)
    }

    /// Return purpose only when it still seals every public decision field.
    pub fn verified_purpose(&self) -> Option<&DecisionPurpose> {
        let purpose = self.purpose.as_ref()?;
        let bytes = to_canonical_bytes(self).ok()?;
        (Digest::blake3(&bytes) == purpose.decision).then_some(purpose)
    }

    pub(crate) fn with_qualification_purpose(
        self,
        purpose: ControlQualificationPurpose,
    ) -> Result<Self, CanonicalError> {
        self.seal(DecisionPurposeKind::ControlQualification(purpose))
    }

    fn seal(mut self, kind: DecisionPurposeKind) -> Result<Self, CanonicalError> {
        let decision = Digest::blake3(&to_canonical_bytes(&self)?);
        self.purpose = Some(DecisionPurpose { kind, decision });
        Ok(self)
    }
}

/// Which immutable calibration vector one candidate dispatch exercises.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QualificationVector {
    /// The artifact-declared input that the control must admit.
    KnownGood,
    /// The artifact-declared violation that the control must deny.
    PlantedViolation,
}

/// Opaque purpose proven by the policy path that produced a decision.
///
/// Callers can inspect and preserve this value but cannot manufacture the
/// exceptional qualification variant. The dispatcher refuses decisions whose
/// in-process purpose is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPurpose {
    kind: DecisionPurposeKind,
    decision: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DecisionPurposeKind {
    Operational,
    ControlQualification(ControlQualificationPurpose),
}

impl DecisionPurpose {
    /// True only for an ordinary active-generation or bootstrap decision.
    pub const fn is_operational(&self) -> bool {
        matches!(&self.kind, DecisionPurposeKind::Operational)
    }

    /// Exact qualification purpose, when this decision came from that path.
    pub const fn qualification_purpose(&self) -> Option<&ControlQualificationPurpose> {
        match &self.kind {
            DecisionPurposeKind::Operational => None,
            DecisionPurposeKind::ControlQualification(purpose) => Some(purpose),
        }
    }
}

/// Exact exceptional authority carried from policy evaluation to storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlQualificationPurpose {
    capability: Digest,
    vector: QualificationVector,
    generation: RuntimeGenerationId,
    replay_domain: String,
    expires_at: Timestamp,
    control_run: ControlRun,
}

impl ControlQualificationPurpose {
    pub(crate) fn new(
        capability: Digest,
        vector: QualificationVector,
        generation: RuntimeGenerationId,
        replay_domain: String,
        expires_at: Timestamp,
        control_run: ControlRun,
    ) -> Self {
        Self {
            capability,
            vector,
            generation,
            replay_domain,
            expires_at,
            control_run,
        }
    }

    /// Digest of the opaque checked qualification capability.
    pub fn capability(&self) -> &Digest {
        &self.capability
    }

    /// Immutable detector vector this dispatch exercises.
    pub const fn vector(&self) -> QualificationVector {
        self.vector
    }

    /// Inactive candidate generation this dispatch may use.
    pub fn generation(&self) -> &RuntimeGenerationId {
        &self.generation
    }

    /// Exact signed operation-intent digest admitted for this vector.
    pub fn intent(&self) -> &Digest {
        &self.control_run.input_digest
    }

    /// Vector-specific replay and accounting domain.
    pub fn replay_domain(&self) -> &str {
        &self.replay_domain
    }

    /// Latest instant at which the exceptional dispatch remains authorized.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Actual target-control invocation produced by the policy decision point.
    pub fn control_run(&self) -> &ControlRun {
        &self.control_run
    }
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

#[cfg(test)]
mod decision_tests {
    use super::PolicyDecision;
    use politeia_core::{Digest, PolicyBundleId, PrincipalId};

    fn decision() -> PolicyDecision {
        PolicyDecision::operational(
            PolicyBundleId::new(),
            Digest::blake3(b"policy"),
            Digest::blake3(b"intent"),
            Digest::blake3(b"subject"),
            Digest::blake3(b"population"),
            PrincipalId::new(),
            true,
            vec!["binding".to_string()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec!["clean".to_string()],
        )
        .expect("fixture decision encodes")
    }

    #[test]
    fn ordinary_wire_shape_omits_in_process_purpose() {
        let decision = decision();
        let value = serde_json::to_value(&decision).expect("fixture decision serializes");
        let object = value.as_object().expect("decision wire is an object");
        assert_eq!(object.len(), 12);
        assert!(!object.contains_key("purpose"));

        let restored: PolicyDecision =
            serde_json::from_value(value).expect("ordinary decision wire still decodes");
        assert!(restored.verified_purpose().is_none());
    }

    #[test]
    fn public_field_mutation_invalidates_private_provenance() {
        let mutations: [fn(&mut PolicyDecision); 2] = [
            |decision: &mut PolicyDecision| decision.allowed = false,
            |decision: &mut PolicyDecision| decision.reasons.push("forged".to_string()),
        ];
        for mutate in mutations {
            let mut decision = decision();
            assert!(decision.verified_purpose().is_some());
            mutate(&mut decision);
            assert!(decision.verified_purpose().is_none());
        }
    }
}
