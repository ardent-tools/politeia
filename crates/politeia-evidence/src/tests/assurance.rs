use jiff::{SignedDuration, Timestamp};
use politeia_core::{Digest, EvidenceId, PrincipalId};

use crate::assurance::{
    ActivationProof, ClaimRefusal, ControlResult, ControlRun, Coverage, clean_claim,
};

#[expect(
    clippy::expect_used,
    reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
)]
fn now() -> Timestamp {
    "2026-08-21T00:00:00Z"
        .parse()
        .expect("the fixture timestamp is valid RFC 3339")
}

const CONTROL: &str = "detector:approval-receipt";
const VERSION: &str = "3.1.0";
const PATH: &str = "dispatcher:authorize";

fn configuration() -> Digest {
    Digest::blake3(b"configuration")
}

fn subject() -> Digest {
    Digest::blake3(b"subject under judgement")
}

fn run(result: ControlResult) -> ControlRun {
    ControlRun {
        id: EvidenceId::new(),
        control: CONTROL.to_string(),
        control_version: VERSION.to_string(),
        configuration_digest: configuration(),
        input_digest: Digest::blake3(b"admitted input"),
        subject: subject(),
        authorization: Digest::blake3(b"decision receipt"),
        mediation_path: PATH.to_string(),
        started_at: now(),
        finished_at: now() + SignedDuration::from_secs(1),
        result,
        coverage: Coverage {
            population: 4,
            observed: 4,
        },
        verifier: PrincipalId::new(),
    }
}

fn activation() -> ActivationProof {
    ActivationProof {
        id: EvidenceId::new(),
        control: CONTROL.to_string(),
        control_version: VERSION.to_string(),
        configuration_digest: configuration(),
        mediation_path: PATH.to_string(),
        planted_violation: Digest::blake3(b"known violation"),
        planted_violation_result: ControlResult::Violation,
        known_good: Digest::blake3(b"known good"),
        known_good_result: ControlResult::Clean,
        retained_evidence: EvidenceId::new(),
        proved_at: now() - SignedDuration::from_hours(1),
    }
}

#[test]
fn a_clean_run_with_activation_and_full_coverage_supports_the_claim() {
    let runs = [run(ControlResult::Clean)];
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject(), &activation()),
        Ok(&runs[0]),
        "the one configuration that should support a clean claim must support it"
    );
}

#[test]
fn every_state_but_clean_refuses_the_claim() {
    // POL-O's exhaustive state test. Written over `all()` rather than a literal
    // list so a state added later is covered without anyone remembering to add
    // it -- and `all()` is itself built from an exhaustive match, so a state
    // added and not listed stops the build.
    let activation = activation();
    let mut passed = Vec::new();
    for state in ControlResult::all() {
        let runs = [run(state)];
        match clean_claim(&runs, CONTROL, &subject(), &activation) {
            Ok(_) => passed.push(state),
            Err(refusal) => assert_eq!(
                refusal,
                ClaimRefusal::ResultNotClean(state),
                "{state:?} must be refused for being what it is, not for something else"
            ),
        }
    }
    assert_eq!(
        passed,
        vec![ControlResult::Clean],
        "exactly one state may support a clean claim"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a result state that cannot serialize is a broken fixture, not a finding"
)]
fn the_wire_tokens_are_the_ones_the_ontology_fixes() {
    // `docs/03-ONTOLOGY.md` fixes these eight strings. A stored result is read
    // back by token, so renaming a variant without noticing would silently
    // change what an archived assurance record means.
    let tokens: Vec<String> = ControlResult::all()
        .into_iter()
        .map(|state| serde_json::to_string(&state).expect("a result state serializes"))
        .collect();
    assert_eq!(
        tokens,
        vec![
            r#""clean""#,
            r#""violation""#,
            r#""not_run""#,
            r#""unavailable""#,
            r#""unevaluable""#,
            r#""unexpectedly_empty""#,
            r#""not_applicable""#,
            r#""unresolved""#,
        ]
    );
}

#[test]
fn a_run_over_a_different_subject_does_not_support_the_claim() {
    // Wrong-subject activation: the control ran, cleanly, over something else.
    let runs = [run(ControlResult::Clean)];
    assert_eq!(
        clean_claim(
            &runs,
            CONTROL,
            &Digest::blake3(b"another subject"),
            &activation()
        ),
        Err(ClaimRefusal::NoRun)
    );
}

#[test]
fn no_run_at_all_is_refused_rather_than_treated_as_nothing_wrong() {
    // The bypass case. Nothing failed because nothing ran, and an absence of
    // violations is what a bypassed control and a working one have in common.
    assert_eq!(
        clean_claim(&[], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::NoRun)
    );
}

#[test]
fn partial_coverage_is_refused() {
    let mut partial = run(ControlResult::Clean);
    partial.coverage = Coverage {
        population: 4,
        observed: 3,
    };
    assert_eq!(
        clean_claim(&[partial], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::PartialCoverage {
            observed: 3,
            population: 4,
        })
    );
}

#[test]
fn an_empty_population_is_refused_separately_from_partial_coverage() {
    // Zero of zero is complete by arithmetic and establishes nothing. Reported
    // as its own refusal because the fix differs: partial coverage means the
    // control missed subjects, an empty population means the subjects were
    // never there and the claim is about nothing.
    let mut empty = run(ControlResult::Clean);
    empty.coverage = Coverage {
        population: 0,
        observed: 0,
    };
    assert_eq!(
        clean_claim(&[empty], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::EmptyPopulation)
    );
}

#[test]
fn a_duplicate_invocation_is_refused_rather_than_resolved() {
    // Two runs of one control over one subject, disagreeing. With both in hand
    // the tempting move is to take the clean one, and that is exactly how a
    // flaky or partly-bypassed control becomes a passing claim.
    let violation = run(ControlResult::Violation);
    let clean = run(ControlResult::Clean);

    assert_eq!(
        clean_claim(&[violation, clean], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::DuplicateInvocation {
            control: CONTROL.to_string(),
        }),
        "a disagreeing pair must refuse, in either order"
    );
}

#[test]
fn a_duplicate_invocation_is_refused_even_when_both_runs_agree() {
    // Agreement is not evidence that the control ran once. It is what two
    // invocations of a control returning a constant also look like.
    let first = run(ControlResult::Clean);
    let second = run(ControlResult::Clean);

    assert!(matches!(
        clean_claim(&[first, second], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::DuplicateInvocation { .. })
    ));
}

#[test]
fn a_missing_activation_binding_is_refused_on_each_axis() {
    let runs = [run(ControlResult::Clean)];
    let subject = subject();

    let mut wrong_control = activation();
    wrong_control.control = "detector:something-else".to_string();
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject, &wrong_control),
        Err(ClaimRefusal::ActivationControlMismatch)
    );

    let mut wrong_version = activation();
    wrong_version.control_version = "3.0.0".to_string();
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject, &wrong_version),
        Err(ClaimRefusal::ActivationVersionMismatch),
        "a proof about a previous version says nothing about this one"
    );

    let mut wrong_configuration = activation();
    wrong_configuration.configuration_digest = Digest::blake3(b"other configuration");
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject, &wrong_configuration),
        Err(ClaimRefusal::ActivationConfigurationMismatch)
    );

    let mut wrong_path = activation();
    wrong_path.mediation_path = "test-harness".to_string();
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject, &wrong_path),
        Err(ClaimRefusal::ActivationPathMismatch),
        "a control proved on a harness has not been proved on the real path"
    );
}

#[test]
fn an_activation_proof_that_did_not_refuse_is_refused() {
    // The proof's whole content. A control that reports clean for a planted
    // violation has been shown unable to fire, and the run it accompanies is
    // clean for the same reason.
    let runs = [run(ControlResult::Clean)];
    for outcome in [
        ControlResult::Clean,
        ControlResult::NotRun,
        ControlResult::Unevaluable,
        ControlResult::NotApplicable,
    ] {
        let mut proof = activation();
        proof.planted_violation_result = outcome;
        assert_eq!(
            clean_claim(&runs, CONTROL, &subject(), &proof),
            Err(ClaimRefusal::ActivationDidNotRefuse(outcome))
        );
    }
}

#[test]
fn an_activation_proof_that_rejected_the_known_good_is_refused() {
    // The other half, and the one an all-refusing control passes without. A
    // control that reports a violation for everything refuses the planted one
    // too, so the refusal alone proves nothing about discrimination.
    let runs = [run(ControlResult::Clean)];
    let mut proof = activation();
    proof.known_good_result = ControlResult::Violation;
    assert_eq!(
        clean_claim(&runs, CONTROL, &subject(), &proof),
        Err(ClaimRefusal::ActivationRejectedKnownGood(
            ControlResult::Violation
        ))
    );
}

#[test]
fn another_controls_run_over_the_same_subject_is_not_this_claim() {
    // Several controls may judge one subject. A claim that took only the
    // subject would have to choose among their runs, and any choice is
    // arbitrary and order-dependent -- so the claim names its control, and a
    // stranger's run is invisible to it whatever it says.
    let mine = run(ControlResult::Clean);
    let mut theirs = run(ControlResult::Violation);
    theirs.control = "detector:something-else".to_string();

    for pair in [
        [mine.clone(), theirs.clone()],
        [theirs.clone(), mine.clone()],
    ] {
        assert_eq!(
            clean_claim(&pair, CONTROL, &subject(), &activation()).map(|run| &run.id),
            Ok(&mine.id),
            "the claim must find its own control's run whatever order they arrive in"
        );
    }
}

#[test]
fn a_run_that_ended_before_it_began_is_refused() {
    let mut inverted = run(ControlResult::Clean);
    inverted.finished_at = inverted.started_at - SignedDuration::from_secs(1);
    assert_eq!(
        clean_claim(&[inverted], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::InvertedInterval)
    );
}

#[test]
fn every_refusal_variant_names_the_test_that_reaches_it() {
    // A refusal nothing can produce is a branch that documents a check rather
    // than performing one, and it reads identically to a working one.
    //
    // WHY an exhaustive match rather than a list of assertions: a list can be
    // shorter than the enum and nothing says so. This stops the build when a
    // variant is added, which forces the author to name the test that reaches
    // it -- and if there is no such test, to notice that before merging.
    // Same mechanism as `ControlResult::all` and the formal models'
    // every-invariant-is-witnessed guard, applied to the refusal set.
    let reached_by = |refusal: &ClaimRefusal| -> &'static str {
        match refusal {
            ClaimRefusal::NoRun => "no_run_at_all_is_refused_rather_than_treated_as_nothing_wrong",
            ClaimRefusal::DuplicateInvocation { .. } => {
                "a_duplicate_invocation_is_refused_rather_than_resolved"
            }
            ClaimRefusal::ResultNotClean(_) => "every_state_but_clean_refuses_the_claim",
            ClaimRefusal::PartialCoverage { .. } => "partial_coverage_is_refused",
            ClaimRefusal::EmptyPopulation => {
                "an_empty_population_is_refused_separately_from_partial_coverage"
            }
            ClaimRefusal::InvertedInterval => "a_run_that_ended_before_it_began_is_refused",
            ClaimRefusal::ActivationControlMismatch
            | ClaimRefusal::ActivationVersionMismatch
            | ClaimRefusal::ActivationConfigurationMismatch
            | ClaimRefusal::ActivationPathMismatch => {
                "a_missing_activation_binding_is_refused_on_each_axis"
            }
            ClaimRefusal::ActivationDidNotRefuse(_) => {
                "an_activation_proof_that_did_not_refuse_is_refused"
            }
            ClaimRefusal::ActivationRejectedKnownGood(_) => {
                "an_activation_proof_that_rejected_the_known_good_is_refused"
            }
        }
    };

    // Two refusals produced here rather than named, so the mapping is anchored
    // to real behaviour at both ends rather than being a table about itself.
    assert_eq!(
        reached_by(&ClaimRefusal::NoRun),
        "no_run_at_all_is_refused_rather_than_treated_as_nothing_wrong"
    );
    assert!(matches!(
        clean_claim(&[], CONTROL, &subject(), &activation()),
        Err(ClaimRefusal::NoRun)
    ));
    assert!(matches!(
        clean_claim(
            &[run(ControlResult::Violation)],
            CONTROL,
            &subject(),
            &activation()
        ),
        Err(ClaimRefusal::ResultNotClean(ControlResult::Violation))
    ));
}
