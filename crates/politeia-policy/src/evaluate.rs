//! Evaluating policy bindings into one normalized decision.
//!
//! A binding says *where a clause applies, which detectors produce admissible
//! evidence, and what consequence follows*. Evaluation is turning a set of them
//! into a single answer about one operation, and the whole difficulty is that
//! the answer must not be more permissive than any of its inputs.
//!
//! Three rules from the corpus shape it, and each is a way a permissive answer
//! gets manufactured out of stricter parts:
//!
//! - `AGENTS.md`: *do not make a heuristic blocking without explicit detector
//!   assurance and calibration.* A binding whose evidence is a guess may advise;
//!   it may not deny.
//! - `docs/06-POLICY_COMPILER.md`: *blocking authority is a property of the
//!   binding, not inherent in the detector.* A binding may apply only what its
//!   hardening rung authorises, which [`BindingAuthority`] already guarantees.
//! - `AGENTS.md`: *do not widen delegation or policy through defaults.* A
//!   binding naming a detector nobody declared is unevaluable, and unevaluable
//!   fails closed rather than falling through to permitted.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::{Digest, PolicyBundleId, PrincipalId};

use crate::hardening::HardeningState;
use crate::{Consequence, DetectorSpec, EvidenceClass, PolicyBinding, PolicyDecision, Waiver};

/// One operation, as policy sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationSubject {
    /// The policy bundle in force.
    pub bundle: PolicyBundleId,
    /// Digest of the exact bundle bytes.
    pub policy_digest: Digest,
    /// Digest of the normalized operation intent.
    pub intent_digest: Digest,
    /// The principal the operation is for.
    pub principal: PrincipalId,
    /// The scopes the operation touches.
    pub scopes: BTreeSet<String>,
    /// When the decision is being made.
    pub at: Timestamp,
}

/// Why a binding could not be evaluated.
///
/// Every one of these fails closed. `AGENTS.md` forbids widening policy through
/// defaults, and an input nobody can interpret is exactly where a default would
/// otherwise be supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unevaluable {
    /// The binding names a detector the bundle does not declare.
    UnknownDetector {
        /// The binding.
        binding: String,
        /// The detector it named.
        detector: String,
    },
    /// The binding names no detector at all.
    ///
    /// A binding with no evidence source produces no evidence, and a
    /// consequence resting on none is an assertion rather than a finding.
    NoDetector {
        /// The binding.
        binding: String,
    },
    /// The binding would block on evidence that is a guess.
    ///
    /// The detector's evidence class is heuristic, or it has not been
    /// calibrated against adversarial fixtures, and the binding's consequence
    /// blocks. It may advise instead; it may not deny.
    HeuristicBlocking {
        /// The binding.
        binding: String,
        /// The detector whose assurance is insufficient.
        detector: String,
    },
}

impl std::fmt::Display for Unevaluable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unevaluable::UnknownDetector { binding, detector } => write!(
                formatter,
                "binding {binding} names detector {detector}, which the bundle does not declare"
            ),
            Unevaluable::NoDetector { binding } => {
                write!(formatter, "binding {binding} names no detector")
            }
            Unevaluable::HeuristicBlocking { binding, detector } => write!(
                formatter,
                "binding {binding} blocks on {detector}, whose evidence is heuristic or uncalibrated"
            ),
        }
    }
}

impl std::error::Error for Unevaluable {}

/// Whether a waiver excuses a binding for this subject.
fn waives(waiver: &Waiver, binding: &PolicyBinding, subject: &EvaluationSubject) -> bool {
    // Parsed rather than compared as text: `2026-08-21T00:00:00Z` and
    // `2026-08-21T00:00:00.000Z` are one instant and two strings, and a string
    // comparison would silently treat an unexpired waiver as expired or the
    // reverse depending on which spelling was stored.
    let Ok(expires_at) = waiver.expires_at_rfc3339.parse::<Timestamp>() else {
        return false;
    };
    waiver.binding_id == binding.id
        && subject.scopes.contains(&waiver.scope)
        && subject.at < expires_at
}

/// Whether a detector's evidence is strong enough to block on.
fn may_block(detector: &DetectorSpec) -> bool {
    match detector.evidence_class {
        EvidenceClass::Substance | EvidenceClass::FormalProof => true,
        EvidenceClass::StructuralProxy | EvidenceClass::LexicalProxy => {
            detector.adversarially_calibrated
        }
        EvidenceClass::Heuristic => false,
    }
}

/// Evaluate every applicable binding into one decision.
///
/// # Errors
///
/// Returns the first [`Unevaluable`] input. Nothing is decided from a partial
/// evaluation: a decision assembled from the bindings that happened to be
/// interpretable is more permissive than the policy it claims to apply, and
/// says nothing about the ones it skipped.
///
/// Time: O(b·d log n) for b bindings of d detectors against n declared.
/// Space: O(b).
pub fn evaluate(
    subject: &EvaluationSubject,
    bindings: &[PolicyBinding],
    detectors: &BTreeMap<String, DetectorSpec>,
    waivers: &[Waiver],
) -> Result<PolicyDecision, Unevaluable> {
    let mut contributing = Vec::new();
    let mut reasons = Vec::new();
    let mut allowed = true;

    for binding in bindings {
        if !subject.scopes.contains(&binding.scope) {
            continue;
        }
        if binding.detector_ids.is_empty() {
            return Err(Unevaluable::NoDetector {
                binding: binding.id.clone(),
            });
        }

        let consequence = binding.authority.consequence();
        let blocks = consequence >= Consequence::RequireReview;
        for detector_id in &binding.detector_ids {
            let Some(detector) = detectors.get(detector_id) else {
                return Err(Unevaluable::UnknownDetector {
                    binding: binding.id.clone(),
                    detector: detector_id.clone(),
                });
            };
            if blocks && !may_block(detector) {
                return Err(Unevaluable::HeuristicBlocking {
                    binding: binding.id.clone(),
                    detector: detector_id.clone(),
                });
            }
        }

        contributing.push(binding.id.clone());
        if let Some(waiver) = waivers
            .iter()
            .find(|waiver| waives(waiver, binding, subject))
        {
            reasons.push(format!(
                "{} waived by {}: {}",
                binding.id, waiver.id, waiver.reason
            ));
            continue;
        }
        if blocks {
            allowed = false;
            reasons.push(format!("{} applies {consequence:?}", binding.id));
        } else {
            reasons.push(format!("{} records {consequence:?}", binding.id));
        }
    }

    Ok(PolicyDecision {
        bundle: subject.bundle.clone(),
        policy_digest: subject.policy_digest.clone(),
        intent_digest: subject.intent_digest.clone(),
        principal: subject.principal.clone(),
        allowed,
        binding_ids: contributing,
        reasons,
    })
}

/// The rung a binding must have climbed before it may block at all.
///
/// Exposed so a caller can ask the question the evaluator answers implicitly:
/// [`BindingAuthority`](crate::hardening::BindingAuthority) already refuses to
/// pair a blocking consequence with a rung that does not authorise it, so by
/// the time a binding exists this is settled. It is here for the reader who
/// wants to know which rung that is without reading the ladder.
pub const fn blocking_requires_at_least() -> HardeningState {
    HardeningState::Enforced
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening::{BindingAuthority, HardeningLadder};

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    const SCOPE: &str = "institution:production";

    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot climb its own ladder is a broken test"
    )]
    fn authority(consequence: Consequence) -> BindingAuthority {
        use crate::hardening::HardeningState;
        let mut ladder = HardeningLadder::new();
        for rung in [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
            HardeningState::Calibrated,
            HardeningState::Advisory,
            HardeningState::Enforced,
        ] {
            ladder.advance(rung).expect("the full climb is legal");
        }
        BindingAuthority::new(ladder, consequence).expect("an enforced binding may apply any")
    }

    fn binding(id: &str, consequence: Consequence, detectors: &[&str]) -> PolicyBinding {
        PolicyBinding {
            id: id.to_string(),
            clause_id: "clause:approved-change".to_string(),
            detector_ids: detectors.iter().map(|d| (*d).to_string()).collect(),
            scope: SCOPE.to_string(),
            authority: authority(consequence),
        }
    }

    fn detector(id: &str, class: EvidenceClass, calibrated: bool) -> DetectorSpec {
        DetectorSpec {
            id: id.to_string(),
            evidence_class: class,
            known_blind_spots: Vec::new(),
            adversarially_calibrated: calibrated,
        }
    }

    fn declared(specs: &[DetectorSpec]) -> BTreeMap<String, DetectorSpec> {
        specs
            .iter()
            .map(|spec| (spec.id.clone(), spec.clone()))
            .collect()
    }

    fn subject() -> EvaluationSubject {
        EvaluationSubject {
            bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            intent_digest: Digest::blake3(b"intent"),
            principal: PrincipalId::new(),
            scopes: BTreeSet::from([SCOPE.to_string()]),
            at: now(),
        }
    }

    fn waiver(id: &str, binding_id: &str, scope: &str, expires: &str) -> Waiver {
        Waiver {
            id: id.to_string(),
            binding_id: binding_id.to_string(),
            scope: scope.to_string(),
            reason: "owner-approved maintenance".to_string(),
            issuer: PrincipalId::new(),
            expires_at_rfc3339: expires.to_string(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not evaluate is a broken test, not a finding"
    )]
    #[test]
    fn a_blocking_binding_denies_and_an_advisory_one_does_not() {
        let substance = detector("detector:receipt", EvidenceClass::Substance, true);
        let specs = declared(&[substance]);

        let denied = evaluate(
            &subject(),
            &[binding("b:deny", Consequence::Deny, &["detector:receipt"])],
            &specs,
            &[],
        )
        .expect("the fixture evaluates");
        assert!(!denied.allowed);
        assert_eq!(denied.binding_ids, vec!["b:deny".to_string()]);

        let advised = evaluate(
            &subject(),
            &[binding(
                "b:advise",
                Consequence::Advisory,
                &["detector:receipt"],
            )],
            &specs,
            &[],
        )
        .expect("the fixture evaluates");
        assert!(advised.allowed, "advice does not deny");
        assert_eq!(
            advised.binding_ids,
            vec!["b:advise".to_string()],
            "an advisory binding still contributed to the decision"
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not evaluate is a broken test, not a finding"
    )]
    #[test]
    fn a_binding_outside_the_subjects_scope_does_not_contribute() {
        let specs = declared(&[detector("detector:receipt", EvidenceClass::Substance, true)]);
        let mut elsewhere = binding("b:elsewhere", Consequence::Deny, &["detector:receipt"]);
        elsewhere.scope = "institution:staging".to_string();

        let decision = evaluate(&subject(), &[elsewhere], &specs, &[]).expect("evaluates");
        assert!(decision.allowed);
        assert!(decision.binding_ids.is_empty());
    }

    #[test]
    fn a_heuristic_detector_may_advise_but_not_block() {
        // `AGENTS.md`: do not make a heuristic blocking without explicit
        // detector assurance and calibration. The binding is otherwise
        // well-formed and fully climbed -- what it lacks is evidence worth
        // blocking on.
        let specs = declared(&[detector("detector:guess", EvidenceClass::Heuristic, true)]);

        assert_eq!(
            evaluate(
                &subject(),
                &[binding("b:guess", Consequence::Deny, &["detector:guess"])],
                &specs,
                &[],
            ),
            Err(Unevaluable::HeuristicBlocking {
                binding: "b:guess".to_string(),
                detector: "detector:guess".to_string(),
            })
        );
        assert!(
            evaluate(
                &subject(),
                &[binding(
                    "b:guess",
                    Consequence::Advisory,
                    &["detector:guess"]
                )],
                &specs,
                &[],
            )
            .is_ok(),
            "the same detector may advise"
        );
    }

    #[test]
    fn a_proxy_must_be_calibrated_before_it_may_block() {
        // A structural proxy is not a guess and not the property itself. What
        // makes it admissible for blocking is having been run against
        // adversarial fixtures, which is exactly what the flag records.
        for (calibrated, blocks) in [(false, false), (true, true)] {
            let specs = declared(&[detector(
                "detector:proxy",
                EvidenceClass::StructuralProxy,
                calibrated,
            )]);
            let result = evaluate(
                &subject(),
                &[binding("b:proxy", Consequence::Deny, &["detector:proxy"])],
                &specs,
                &[],
            );
            assert_eq!(
                result.is_ok(),
                blocks,
                "calibrated={calibrated} should block={blocks}"
            );
        }
    }

    #[test]
    fn a_binding_naming_an_undeclared_detector_fails_closed() {
        assert_eq!(
            evaluate(
                &subject(),
                &[binding(
                    "b:orphan",
                    Consequence::Advisory,
                    &["detector:absent"]
                )],
                &BTreeMap::new(),
                &[],
            ),
            Err(Unevaluable::UnknownDetector {
                binding: "b:orphan".to_string(),
                detector: "detector:absent".to_string(),
            })
        );
    }

    #[test]
    fn a_binding_with_no_detector_fails_closed() {
        // A consequence resting on no evidence source is an assertion rather
        // than a finding.
        assert_eq!(
            evaluate(
                &subject(),
                &[binding("b:bare", Consequence::Advisory, &[])],
                &BTreeMap::new(),
                &[],
            ),
            Err(Unevaluable::NoDetector {
                binding: "b:bare".to_string(),
            })
        );
    }

    #[test]
    fn nothing_is_decided_from_a_partial_evaluation() {
        // The permissive-answer-from-stricter-parts failure. One evaluable
        // denying binding and one unevaluable binding: returning the first
        // alone would be a decision that ignored an input it could not read.
        let specs = declared(&[detector("detector:receipt", EvidenceClass::Substance, true)]);
        let result = evaluate(
            &subject(),
            &[
                binding("b:deny", Consequence::Deny, &["detector:receipt"]),
                binding("b:orphan", Consequence::Advisory, &["detector:absent"]),
            ],
            &specs,
            &[],
        );
        assert!(
            matches!(result, Err(Unevaluable::UnknownDetector { .. })),
            "an unevaluable input must abort the whole decision, got {result:?}"
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not evaluate is a broken test, not a finding"
    )]
    #[test]
    fn a_live_waiver_excuses_and_an_expired_one_does_not() {
        let specs = declared(&[detector("detector:receipt", EvidenceClass::Substance, true)]);
        let bindings = [binding("b:deny", Consequence::Deny, &["detector:receipt"])];

        let live = evaluate(
            &subject(),
            &bindings,
            &specs,
            &[waiver("w:1", "b:deny", SCOPE, "2026-08-22T00:00:00Z")],
        )
        .expect("evaluates");
        assert!(live.allowed, "a live waiver excuses the binding");

        let expired = evaluate(
            &subject(),
            &bindings,
            &specs,
            &[waiver("w:1", "b:deny", SCOPE, "2026-08-20T00:00:00Z")],
        )
        .expect("evaluates");
        assert!(!expired.allowed, "an expired waiver excuses nothing");
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not evaluate is a broken test, not a finding"
    )]
    #[test]
    fn a_waiver_for_another_scope_or_an_unreadable_expiry_excuses_nothing() {
        let specs = declared(&[detector("detector:receipt", EvidenceClass::Substance, true)]);
        let bindings = [binding("b:deny", Consequence::Deny, &["detector:receipt"])];

        for bad in [
            waiver(
                "w:scope",
                "b:deny",
                "institution:staging",
                "2026-08-22T00:00:00Z",
            ),
            waiver("w:unreadable", "b:deny", SCOPE, "next Tuesday"),
        ] {
            let decision = evaluate(&subject(), &bindings, &specs, std::slice::from_ref(&bad))
                .expect("evaluates");
            assert!(!decision.allowed, "{} must not excuse the binding", bad.id);
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not evaluate is a broken test, not a finding"
    )]
    #[test]
    fn an_expiry_is_compared_as_an_instant_rather_than_as_text() {
        // `2026-08-22T00:00:00Z` and `2026-08-22T00:00:00.000Z` are one instant
        // and two strings. Comparing text would make a waiver live or expired
        // depending on which spelling was stored.
        let specs = declared(&[detector("detector:receipt", EvidenceClass::Substance, true)]);
        let bindings = [binding("b:deny", Consequence::Deny, &["detector:receipt"])];

        for spelling in ["2026-08-22T00:00:00Z", "2026-08-22T00:00:00.000Z"] {
            let decision = evaluate(
                &subject(),
                &bindings,
                &specs,
                &[waiver("w:1", "b:deny", SCOPE, spelling)],
            )
            .expect("evaluates");
            assert!(decision.allowed, "{spelling} names a live instant");
        }
    }

    #[test]
    fn every_unevaluable_variant_names_the_test_that_reaches_it() {
        let reached_by = |reason: &Unevaluable| -> &'static str {
            match reason {
                Unevaluable::UnknownDetector { .. } => {
                    "a_binding_naming_an_undeclared_detector_fails_closed"
                }
                Unevaluable::NoDetector { .. } => "a_binding_with_no_detector_fails_closed",
                Unevaluable::HeuristicBlocking { .. } => {
                    "a_heuristic_detector_may_advise_but_not_block"
                }
            }
        };
        assert_eq!(
            reached_by(&Unevaluable::NoDetector {
                binding: String::new()
            }),
            "a_binding_with_no_detector_fails_closed"
        );
    }
}
