#![expect(
    clippy::expect_used,
    reason = "assurance fixtures must fail immediately when admission invariants break"
)]

use jiff::SignedDuration;
use politeia_core::trust::{AdmissionError, AdmissionKind};
use politeia_core::{Digest, EvidenceId, PolicyBundleId};

use crate::assurance::{
    ActivationProof, AssuranceAdmissionRefusal, AuthorizedControlRun, ClaimRefusal, ControlResult,
    ControlRun, Coverage, RUN_POLICY_CONTROL_ACTION, VERIFY_POLICY_CONTROL_ACTION,
    VerifiedActivation, clean_claim, policy_control_resource,
};
use crate::authority::AuthorityRefusal;
use crate::test_support::TestAuthority;

const CONTROL: &str = "detector:approval-receipt";
const VERSION: &str = "3.1.0";
const PATH: &str = "dispatcher:authorize";

struct AssuranceFixture {
    trust: TestAuthority,
    policy: PolicyBundleId,
    policy_digest: Digest,
    population: Digest,
}

impl AssuranceFixture {
    fn new() -> Self {
        Self {
            trust: TestAuthority::new(),
            policy: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            population: Digest::blake3(b"population"),
        }
    }

    fn subject(&self) -> Digest {
        Digest::blake3(b"subject under judgement")
    }

    fn run(&self, result: ControlResult) -> ControlRun {
        ControlRun {
            id: EvidenceId::new(),
            control: CONTROL.to_string(),
            control_version: VERSION.to_string(),
            configuration_digest: Digest::blake3(b"configuration"),
            policy: self.policy.clone(),
            policy_digest: self.policy_digest.clone(),
            input_digest: Digest::blake3(b"admitted input"),
            subject: self.subject(),
            population: self.population.clone(),
            authorization: Digest::blake3(b"decision receipt"),
            mediation_path: PATH.to_string(),
            started_at: self.trust.now() - SignedDuration::from_mins(5),
            finished_at: self.trust.now() - SignedDuration::from_mins(4),
            result,
            coverage: Coverage {
                population: 4,
                observed: 4,
            },
        }
    }

    fn activation(&self) -> ActivationProof {
        ActivationProof {
            id: EvidenceId::new(),
            control: CONTROL.to_string(),
            control_version: VERSION.to_string(),
            configuration_digest: Digest::blake3(b"configuration"),
            policy: self.policy.clone(),
            policy_digest: self.policy_digest.clone(),
            population: Digest::blake3(b"adversarial fixtures"),
            mediation_path: PATH.to_string(),
            planted_violation: Digest::blake3(b"known violation"),
            planted_violation_result: ControlResult::Violation,
            known_good: Digest::blake3(b"known good"),
            known_good_result: ControlResult::Clean,
            retained_evidence: EvidenceId::new(),
            proved_at: self.trust.now() - SignedDuration::from_hours(1),
        }
    }
}

#[test]
fn a_clean_run_needs_authorized_run_and_separate_verified_activation() {
    let fixture = AssuranceFixture::new();
    let run = fixture.trust.admit(
        AdmissionKind::ControlRun,
        &fixture.trust.producer,
        fixture.run(ControlResult::Clean),
    );
    let run_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.producer.clone(),
            RUN_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let activation = fixture.trust.admit(
        AdmissionKind::ActivationProof,
        &fixture.trust.verifier,
        fixture.activation(),
    );
    let activation_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.verifier.clone(),
            VERIFY_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let context = fixture.trust.context();
    let run = AuthorizedControlRun::admit(&run, &run_grant, &context)
        .expect("run has exact producer authority");
    let activation = VerifiedActivation::admit(&activation, &activation_grant, &context)
        .expect("activation has exact verifier authority");
    assert_eq!(
        clean_claim(&[run], CONTROL, &fixture.subject(), &activation)
            .expect("the exact clean claim is supported")
            .result,
        ControlResult::Clean,
        "only the admitted clean run supports the claim"
    );
}

#[test]
fn forged_activation_fails_before_assurance_admission() {
    let fixture = AssuranceFixture::new();
    let mut wire = fixture.trust.sign(
        AdmissionKind::ActivationProof,
        &fixture.trust.verifier,
        fixture.activation(),
    );
    wire.payload.configuration_digest = Digest::blake3(b"forged configuration");
    assert!(
        matches!(
            fixture
                .trust
                .admit_wire(AdmissionKind::ActivationProof, wire),
            Err(AdmissionError::InvalidSignature)
        ),
        "a forged calibration payload cannot cross signed admission"
    );
}

#[test]
fn wrong_control_authority_is_refused() {
    let fixture = AssuranceFixture::new();
    let run = fixture.trust.admit(
        AdmissionKind::ControlRun,
        &fixture.trust.producer,
        fixture.run(ControlResult::Clean),
    );
    let wrong = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.producer.clone(),
            "observe-only",
            policy_control_resource(CONTROL),
        ),
    );
    assert!(
        matches!(
            AuthorizedControlRun::admit(&run, &wrong, &fixture.trust.context()),
            Err(AssuranceAdmissionRefusal::Authority(
                AuthorityRefusal::ActionScopeMismatch
            ))
        ),
        "an installed signer still needs the exact delegated control action"
    );
}

#[test]
fn every_nonclean_state_remains_a_distinct_refusal() {
    let fixture = AssuranceFixture::new();
    let run_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.producer.clone(),
            RUN_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let activation = fixture.trust.admit(
        AdmissionKind::ActivationProof,
        &fixture.trust.verifier,
        fixture.activation(),
    );
    let activation_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.verifier.clone(),
            VERIFY_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let context = fixture.trust.context();
    let activation = VerifiedActivation::admit(&activation, &activation_grant, &context)
        .expect("activation is valid");
    let mut clean_count = 0;
    for state in ControlResult::all() {
        let admitted = fixture.trust.admit(
            AdmissionKind::ControlRun,
            &fixture.trust.producer,
            fixture.run(state),
        );
        let run = AuthorizedControlRun::admit(&admitted, &run_grant, &context)
            .expect("each typed result can be admitted without changing its meaning");
        match clean_claim(&[run], CONTROL, &fixture.subject(), &activation) {
            Ok(_) => clean_count += 1,
            Err(ClaimRefusal::ResultNotClean(found)) => assert_eq!(
                found, state,
                "the refusal must preserve the exact source state"
            ),
            Err(other) => panic!("state {state:?} reached the wrong refusal: {other}"),
        }
    }
    assert_eq!(clean_count, 1, "clean is the sole successful state");
}

#[test]
fn self_attested_activation_is_refused() {
    let fixture = AssuranceFixture::new();
    let run = fixture.trust.admit(
        AdmissionKind::ControlRun,
        &fixture.trust.producer,
        fixture.run(ControlResult::Clean),
    );
    let run_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.producer.clone(),
            RUN_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let activation = fixture.trust.admit(
        AdmissionKind::ActivationProof,
        &fixture.trust.producer,
        fixture.activation(),
    );
    let activation_grant = fixture.trust.admit(
        AdmissionKind::Delegation,
        &fixture.trust.owner,
        fixture.trust.grant(
            fixture.trust.producer.clone(),
            VERIFY_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let context = fixture.trust.context();
    let run = AuthorizedControlRun::admit(&run, &run_grant, &context).expect("run is authorized");
    let activation = VerifiedActivation::admit(&activation, &activation_grant, &context)
        .expect("activation signer has a verification grant");
    assert!(
        matches!(
            clean_claim(&[run], CONTROL, &fixture.subject(), &activation),
            Err(ClaimRefusal::SelfAttestedActivation)
        ),
        "a producer cannot satisfy its own activation obligation"
    );
}

#[test]
fn result_wire_tokens_remain_the_ontology_contract() {
    let tokens: Vec<String> = ControlResult::all()
        .into_iter()
        .map(|state| serde_json::to_string(&state).expect("state serializes"))
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
        ],
        "stored result tokens are stable"
    );
}
