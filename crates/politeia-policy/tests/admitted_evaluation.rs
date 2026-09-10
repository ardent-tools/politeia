#![expect(
    clippy::expect_used,
    reason = "signed policy fixtures must fail immediately when their fixed invariants break"
)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::trust::{
    AdmissionKind, Admitted, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey,
};
use politeia_core::{
    DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId, ResourceBudget,
};
use politeia_evidence::assurance::{
    ActivationProof, AuthorizedControlRun, ControlResult, ControlRun, Coverage,
    RUN_POLICY_CONTROL_ACTION, VERIFY_POLICY_CONTROL_ACTION, VerifiedActivation,
    policy_control_resource,
};
use politeia_evidence::authority::{AuthorityContext, AuthorityRefusal, institution_audience};
use politeia_policy::evaluate::{
    ControlRef, EvaluationEvidence, EvaluationSubject, EvidenceAxis, Unevaluable, evaluate,
};
use politeia_policy::hardening::{BindingAuthority, HardeningLadder, HardeningState};
use politeia_policy::waiver::{
    DelegatedWaiver, WAIVE_POLICY_BINDING_ACTION, WaiverAdmissionRefusal, policy_binding_resource,
};
use politeia_policy::{
    Consequence, DetectorSpec, EvidenceClass, PolicyBinding, PolicyDecision, Waiver,
};
use serde::Serialize;

const CONTROL: &str = "detector:approval-receipt";
const BINDING: &str = "binding:approved-change";
const SCOPE: &str = "institution:production";
const VERSION: &str = "3.1.0";
const PATH: &str = "dispatcher:authorize";

struct Fixture {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    owner: PrincipalId,
    actor: PrincipalId,
    producer: PrincipalId,
    verifier: PrincipalId,
    waiver_signer: PrincipalId,
    owner_key: SigningKey,
    actor_key: SigningKey,
    producer_key: SigningKey,
    verifier_key: SigningKey,
    waiver_key: SigningKey,
    anchors: InstitutionTrustAnchors,
    now: Timestamp,
    bundle: PolicyBundleId,
    policy_digest: Digest,
    intent: Digest,
    subject: Digest,
    population: Digest,
    calibration_population: Digest,
}

impl Fixture {
    fn new() -> Self {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let owner = PrincipalId::new();
        let actor = PrincipalId::new();
        let producer = PrincipalId::new();
        let verifier = PrincipalId::new();
        let waiver_signer = PrincipalId::new();
        let owner_key = SigningKey::from_bytes(&[10; 32]);
        let actor_key = SigningKey::from_bytes(&[20; 32]);
        let producer_key = SigningKey::from_bytes(&[30; 32]);
        let verifier_key = SigningKey::from_bytes(&[40; 32]);
        let waiver_key = SigningKey::from_bytes(&[50; 32]);
        let permissions = BTreeSet::from([
            AdmissionKind::Delegation,
            AdmissionKind::ControlRun,
            AdmissionKind::ActivationProof,
            AdmissionKind::Waiver,
        ]);
        let principal_keys = [
            (&owner, &owner_key),
            (&actor, &actor_key),
            (&producer, &producer_key),
            (&verifier, &verifier_key),
            (&waiver_signer, &waiver_key),
        ];
        let trusted_keys = principal_keys.map(|(principal, key)| {
            TrustedSigningKey::new(
                principal.clone(),
                key.verifying_key().to_bytes(),
                permissions.clone(),
            )
            .expect("fixture signing key is valid")
        });
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            institution.clone(),
            workspace.clone(),
            trusted_keys,
        )
        .expect("fixture principals are unique");
        Self {
            institution,
            workspace,
            owner,
            actor,
            producer,
            verifier,
            waiver_signer,
            owner_key,
            actor_key,
            producer_key,
            verifier_key,
            waiver_key,
            anchors,
            now: "2026-08-21T00:00:00Z"
                .parse()
                .expect("fixture timestamp is RFC 3339"),
            bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            intent: Digest::blake3(b"intent"),
            subject: Digest::blake3(b"subject"),
            population: Digest::blake3(b"population"),
            calibration_population: Digest::blake3(b"adversarial population"),
        }
    }

    fn context(&self) -> AuthorityContext {
        AuthorityContext::new(
            self.institution.clone(),
            self.workspace.clone(),
            self.owner.clone(),
            self.now,
        )
    }

    fn subject(&self) -> EvaluationSubject {
        EvaluationSubject {
            institution: self.institution.clone(),
            workspace: self.workspace.clone(),
            bundle: self.bundle.clone(),
            policy_digest: self.policy_digest.clone(),
            intent_digest: self.intent.clone(),
            subject: self.subject.clone(),
            population: self.population.clone(),
            principal: self.actor.clone(),
            scopes: BTreeSet::from([SCOPE.to_string()]),
            at: self.now,
        }
    }

    fn binding(&self) -> PolicyBinding {
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
            ladder.advance(rung).expect("fixture ladder is legal");
        }
        PolicyBinding {
            id: BINDING.to_string(),
            clause_id: "clause:approved-change".to_string(),
            detector_ids: vec![CONTROL.to_string()],
            scope: SCOPE.to_string(),
            authority: BindingAuthority::new(ladder, Consequence::Deny)
                .expect("enforced binding may deny"),
        }
    }

    fn detector(&self) -> DetectorSpec {
        DetectorSpec {
            id: CONTROL.to_string(),
            evidence_class: EvidenceClass::Substance,
            control_version: VERSION.to_string(),
            configuration_digest: Digest::blake3(b"configuration"),
            mediation_path: PATH.to_string(),
            supported_scopes: BTreeSet::from([SCOPE.to_string()]),
            calibration_population: self.calibration_population.clone(),
            known_blind_spots: Vec::new(),
        }
    }

    fn run(&self, result: ControlResult) -> ControlRun {
        ControlRun {
            id: EvidenceId::new(),
            control: CONTROL.to_string(),
            control_version: VERSION.to_string(),
            configuration_digest: Digest::blake3(b"configuration"),
            policy: self.bundle.clone(),
            policy_digest: self.policy_digest.clone(),
            input_digest: self.intent.clone(),
            subject: self.subject.clone(),
            population: self.population.clone(),
            authorization: Digest::blake3(b"control authorization"),
            mediation_path: PATH.to_string(),
            started_at: self.now - SignedDuration::from_mins(5),
            finished_at: self.now - SignedDuration::from_mins(4),
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
            policy: self.bundle.clone(),
            policy_digest: self.policy_digest.clone(),
            population: self.calibration_population.clone(),
            mediation_path: PATH.to_string(),
            planted_violation: Digest::blake3(b"planted violation"),
            planted_violation_result: ControlResult::Violation,
            known_good: Digest::blake3(b"known good"),
            known_good_result: ControlResult::Clean,
            retained_evidence: EvidenceId::new(),
            proved_at: self.now - SignedDuration::from_hours(1),
        }
    }

    fn grant(&self, subject: PrincipalId, action: &str, resource: String) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: self.owner.clone(),
            subject,
            parent: None,
            actions: BTreeSet::from([action.to_string()]),
            resources: BTreeSet::from([resource]),
            effects: BTreeSet::<Effect>::new(),
            data_classes: BTreeSet::<DataClass>::new(),
            audience: BTreeSet::from([institution_audience(&self.institution)]),
            expires_at: self.now + SignedDuration::from_hours(2),
            budget: ResourceBudget {
                wall_ms: Some(0),
                cpu_ms: Some(0),
                memory_bytes: Some(0),
                io_bytes: Some(0),
                network_bytes: Some(0),
                external_cost_microunits: Some(0),
            },
        }
    }

    fn admit<T: Serialize>(
        &self,
        kind: AdmissionKind,
        signer: &PrincipalId,
        payload: T,
    ) -> Admitted<T> {
        let wire = SignedAdmissionWire::sign(
            kind,
            self.institution.clone(),
            self.workspace.clone(),
            signer.clone(),
            payload,
            self.key(signer),
        )
        .expect("fixture payload encodes");
        self.anchors
            .admit_expected(kind, wire)
            .expect("fixture admission is authentic")
    }

    fn key(&self, signer: &PrincipalId) -> &SigningKey {
        for (principal, key) in [
            (&self.owner, &self.owner_key),
            (&self.actor, &self.actor_key),
            (&self.producer, &self.producer_key),
            (&self.verifier, &self.verifier_key),
            (&self.waiver_signer, &self.waiver_key),
        ] {
            if signer == principal {
                return key;
            }
        }
        panic!("fixture signer is not installed")
    }

    fn evaluate_run(
        &self,
        run: ControlRun,
        proof: Option<ActivationProof>,
        activation_signer: &PrincipalId,
    ) -> Result<PolicyDecision, Unevaluable> {
        let run = self.admit(AdmissionKind::ControlRun, &self.producer, run);
        let run_grant = self.admit(
            AdmissionKind::Delegation,
            &self.owner,
            self.grant(
                self.producer.clone(),
                RUN_POLICY_CONTROL_ACTION,
                policy_control_resource(CONTROL),
            ),
        );
        let context = self.context();
        let run = AuthorizedControlRun::admit(&run, &run_grant, &context)
            .expect("fixture run has exact authority");
        let admitted_activation =
            proof.map(|proof| self.admit(AdmissionKind::ActivationProof, activation_signer, proof));
        let activation_grant = admitted_activation.as_ref().map(|_| {
            self.admit(
                AdmissionKind::Delegation,
                &self.owner,
                self.grant(
                    activation_signer.clone(),
                    VERIFY_POLICY_CONTROL_ACTION,
                    policy_control_resource(CONTROL),
                ),
            )
        });
        let activations: Vec<_> = admitted_activation
            .as_ref()
            .zip(activation_grant.as_ref())
            .map(|(activation, grant)| {
                VerifiedActivation::admit(activation, grant, &context)
                    .expect("fixture activation has exact authority")
            })
            .into_iter()
            .collect();
        let runs = [run];
        let evidence = EvaluationEvidence::new(&runs, &activations, &[]);
        evaluate(
            &self.subject(),
            &[self.binding()],
            &BTreeMap::from([(CONTROL.to_string(), self.detector())]),
            &evidence,
        )
    }
}

#[test]
fn clean_real_result_allows_and_violation_denies() {
    let fixture = Fixture::new();
    let clean = fixture
        .evaluate_run(
            fixture.run(ControlResult::Clean),
            Some(fixture.activation()),
            &fixture.verifier,
        )
        .expect("exact clean evidence evaluates");
    assert!(clean.allowed, "a real clean result does not trigger denial");
    assert_eq!(clean.control_runs.len(), 1, "decision binds its run");
    assert_eq!(
        clean.activation_proofs.len(),
        1,
        "blocking-capable clean result binds activation evidence"
    );

    let violation = fixture
        .evaluate_run(
            fixture.run(ControlResult::Violation),
            Some(fixture.activation()),
            &fixture.verifier,
        )
        .expect("exact violation evidence evaluates");
    assert!(
        !violation.allowed,
        "a deny binding reacts to a real violation"
    );
}

#[test]
fn absent_and_each_unresolved_result_have_distinct_refusals() {
    let fixture = Fixture::new();
    let empty = EvaluationEvidence::new(&[], &[], &[]);
    assert_eq!(
        evaluate(
            &fixture.subject(),
            &[fixture.binding()],
            &BTreeMap::from([(CONTROL.to_string(), fixture.detector())]),
            &empty,
        ),
        Err(Unevaluable::MissingControlRun(ControlRef {
            binding: BINDING.to_string(),
            detector: CONTROL.to_string(),
        })),
        "missing evidence is not a clean result"
    );

    for (result, expected) in [
        (
            ControlResult::NotRun,
            Unevaluable::ControlNotRun(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
        (
            ControlResult::Unavailable,
            Unevaluable::ControlUnavailable(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
        (
            ControlResult::Unevaluable,
            Unevaluable::ControlUnevaluable(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
        (
            ControlResult::UnexpectedlyEmpty,
            Unevaluable::ControlUnexpectedlyEmpty(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
        (
            ControlResult::NotApplicable,
            Unevaluable::ControlNotApplicable(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
        (
            ControlResult::Unresolved,
            Unevaluable::ControlUnresolved(ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            }),
        ),
    ] {
        assert_eq!(
            fixture.evaluate_run(
                fixture.run(result),
                Some(fixture.activation()),
                &fixture.verifier,
            ),
            Err(expected),
            "{result:?} retains its semantic identity"
        );
    }
}

#[test]
fn unobserved_and_partial_populations_are_not_clean() {
    let fixture = Fixture::new();
    let mut unobserved = fixture.run(ControlResult::Clean);
    unobserved.coverage.observed = 0;
    assert!(
        matches!(
            fixture.evaluate_run(unobserved, Some(fixture.activation()), &fixture.verifier,),
            Err(Unevaluable::UnobservedPopulation(_))
        ),
        "zero observations cannot become clean"
    );
    let mut partial = fixture.run(ControlResult::Clean);
    partial.coverage.observed = 3;
    assert!(
        matches!(
            fixture.evaluate_run(partial, Some(fixture.activation()), &fixture.verifier,),
            Err(Unevaluable::PartialCleanCoverage { .. })
        ),
        "partial observation cannot become clean"
    );
}

#[test]
fn stale_subject_and_calibration_population_fail_closed() {
    let fixture = Fixture::new();
    let mut stale_run = fixture.run(ControlResult::Clean);
    stale_run.subject = Digest::blake3(b"prior subject");
    assert_eq!(
        fixture.evaluate_run(stale_run, Some(fixture.activation()), &fixture.verifier,),
        Err(Unevaluable::ControlBindingMismatch {
            control: ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            },
            axis: EvidenceAxis::Subject,
        }),
        "a prior subject's clean run cannot be replayed"
    );

    let mut stale_activation = fixture.activation();
    stale_activation.population = Digest::blake3(b"prior calibration corpus");
    assert_eq!(
        fixture.evaluate_run(
            fixture.run(ControlResult::Clean),
            Some(stale_activation),
            &fixture.verifier,
        ),
        Err(Unevaluable::ActivationBindingMismatch {
            control: ControlRef {
                binding: BINDING.to_string(),
                detector: CONTROL.to_string(),
            },
            axis: EvidenceAxis::Population,
        }),
        "a proof for another calibration population is not current activation"
    );
}

#[test]
fn missing_or_self_attested_activation_cannot_support_blocking() {
    let fixture = Fixture::new();
    assert!(
        matches!(
            fixture.evaluate_run(fixture.run(ControlResult::Clean), None, &fixture.verifier),
            Err(Unevaluable::MissingActivationProof(_))
        ),
        "a blocking control needs actual activation evidence"
    );
    assert!(
        matches!(
            fixture.evaluate_run(
                fixture.run(ControlResult::Clean),
                Some(fixture.activation()),
                &fixture.producer,
            ),
            Err(Unevaluable::SelfAttestedActivation(_))
        ),
        "the control producer cannot verify its own activation"
    );
}

#[test]
fn waiver_requires_exact_delegated_authority_and_then_excuses_a_violation() {
    let fixture = Fixture::new();
    let waiver = Waiver {
        id: "waiver:maintenance".to_string(),
        binding_id: BINDING.to_string(),
        policy: fixture.bundle.clone(),
        policy_digest: fixture.policy_digest.clone(),
        subject: fixture.subject.clone(),
        population: fixture.population.clone(),
        scope: SCOPE.to_string(),
        reason: "approved maintenance".to_string(),
        expires_at: fixture.now + SignedDuration::from_hours(1),
    };
    let admitted_waiver = fixture.admit(
        AdmissionKind::Waiver,
        &fixture.waiver_signer,
        waiver.clone(),
    );
    let wrong_grant = fixture.admit(
        AdmissionKind::Delegation,
        &fixture.owner,
        fixture.grant(
            fixture.waiver_signer.clone(),
            "observe-only",
            policy_binding_resource(BINDING),
        ),
    );
    assert!(
        matches!(
            DelegatedWaiver::admit(&admitted_waiver, &wrong_grant, &fixture.context()),
            Err(WaiverAdmissionRefusal::Authority(
                AuthorityRefusal::ActionScopeMismatch
            ))
        ),
        "signature admission alone cannot grant waiver authority"
    );

    let waiver_grant = fixture.admit(
        AdmissionKind::Delegation,
        &fixture.owner,
        fixture.grant(
            fixture.waiver_signer.clone(),
            WAIVE_POLICY_BINDING_ACTION,
            policy_binding_resource(BINDING),
        ),
    );
    let delegated_waiver =
        DelegatedWaiver::admit(&admitted_waiver, &waiver_grant, &fixture.context())
            .expect("waiver has exact delegated authority");
    let admitted_run = fixture.admit(
        AdmissionKind::ControlRun,
        &fixture.producer,
        fixture.run(ControlResult::Violation),
    );
    let run_grant = fixture.admit(
        AdmissionKind::Delegation,
        &fixture.owner,
        fixture.grant(
            fixture.producer.clone(),
            RUN_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let admitted_activation = fixture.admit(
        AdmissionKind::ActivationProof,
        &fixture.verifier,
        fixture.activation(),
    );
    let activation_grant = fixture.admit(
        AdmissionKind::Delegation,
        &fixture.owner,
        fixture.grant(
            fixture.verifier.clone(),
            VERIFY_POLICY_CONTROL_ACTION,
            policy_control_resource(CONTROL),
        ),
    );
    let context = fixture.context();
    let run = AuthorizedControlRun::admit(&admitted_run, &run_grant, &context)
        .expect("run has exact authority");
    let activation = VerifiedActivation::admit(&admitted_activation, &activation_grant, &context)
        .expect("activation has exact authority");
    let runs = [run];
    let activations = [activation];
    let waivers = [delegated_waiver];
    let evidence = EvaluationEvidence::new(&runs, &activations, &waivers);
    let decision = evaluate(
        &fixture.subject(),
        &[fixture.binding()],
        &BTreeMap::from([(CONTROL.to_string(), fixture.detector())]),
        &evidence,
    )
    .expect("all evidence is exact");
    assert!(decision.allowed, "authorized waiver excuses the violation");
    assert_eq!(
        decision.waiver_ids,
        vec![waiver.id],
        "decision binds the exact waiver"
    );
}
