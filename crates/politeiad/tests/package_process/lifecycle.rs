//! Real lifecycle calibration, deliberate failures, and atomic activation.

use jiff::Timestamp;
use politeia_core::{
    DelegationId, Digest, EvidenceId,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assurance::ControlResult;
use politeiad::{
    service_generation::GenerationTransitionAction,
    service_generation_validation::GenerationValidationReport,
};
use tokio_postgres::NoTls;

use super::{
    OperationalFixture, ReferenceFixture, TestResult, require_refusal, run, status_value,
    submit_commissioning, write_request,
};

/// Activate or roll back only after independent public validation calls.
pub(crate) fn activate(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    generation: &Digest,
    kind: &str,
    exercise_refusals: bool,
) -> TestResult {
    let qualifications = match operations.qualifications_for(generation) {
        Some(qualifications) => qualifications,
        None => qualify_candidate(database_url, fixture, operations, generation)?,
    };
    let control = format!("generation:{kind}");
    let authorities = fixture.lifecycle_authorities(&control);
    for (role, delegation) in [
        ("producer", &authorities.run_authority),
        ("verifier", &authorities.proof_authority),
    ] {
        submit_commissioning(
            database_url,
            fixture,
            &format!("{kind}-{role}-authority.json"),
            &serde_json::json!({"kind": "admit_delegation", "delegation": delegation}),
        )?;
    }
    let verifier = validate(database_url, fixture, generation, &control, "verifier")?;
    let calibration = fixture.lifecycle_calibration(&verifier, &authorities);
    let started_at = Timestamp::now();
    let producer = validate(database_url, fixture, generation, &control, "producer")?;
    let mut assurance =
        fixture.lifecycle_assurance(&producer, &calibration, &authorities, started_at);
    assurance.qualifications = qualifications.clone();
    assert_eq!(producer.known_good_result, ControlResult::Clean);
    assert_eq!(producer.planted_violation_result, ControlResult::Violation);
    assert!(producer.coverage.is_complete());
    let snapshot = status_value(database_url, fixture)?;
    let revision = snapshot["revision"]
        .as_i64()
        .ok_or("status omitted revision")?;
    let active: Option<Digest> = serde_json::from_value(snapshot["active_generation"].clone())?;

    if exercise_refusals {
        let mut missing_qualification = assurance.clone();
        missing_qualification.qualifications.clear();
        refuse(
            database_url,
            fixture,
            "lifecycle-missing-control-qualification.json",
            &fixture.activation_request(
                kind,
                generation,
                revision,
                active.as_ref(),
                &missing_qualification,
            ),
            "candidate control qualification coverage differs",
        )?;
        assert_eq!(
            status_value(database_url, fixture)?["active_generation"],
            serde_json::json!(active.clone()),
            "a missing candidate control proof leaves the active pointer unchanged"
        );

        let mut duplicate_qualification = assurance.clone();
        duplicate_qualification.qualifications.push(
            qualifications
                .first()
                .expect("fixture has one proof for its installed detector")
                .clone(),
        );
        refuse(
            database_url,
            fixture,
            "lifecycle-duplicate-control-qualification.json",
            &fixture.activation_request(
                kind,
                generation,
                revision,
                active.as_ref(),
                &duplicate_qualification,
            ),
            "candidate control qualifications duplicate one detector",
        )?;
        assert_eq!(
            status_value(database_url, fixture)?["active_generation"],
            serde_json::json!(active.clone()),
            "a duplicate candidate control proof leaves the active pointer unchanged"
        );

        let requested_action = match kind {
            "activate" => GenerationTransitionAction::Activate,
            "rollback" => GenerationTransitionAction::Rollback,
            _ => return Err("lifecycle action must be activate or rollback".into()),
        };
        let swapped_action = match requested_action {
            GenerationTransitionAction::Activate => GenerationTransitionAction::Rollback,
            GenerationTransitionAction::Rollback => GenerationTransitionAction::Activate,
        };
        let mut missing_transition =
            fixture.activation_request(kind, &generation, revision, active.as_ref(), &assurance);
        missing_transition["request"]
            .as_object_mut()
            .ok_or("activation request is an object")?
            .remove("transition");
        refuse(
            database_url,
            fixture,
            "lifecycle-missing-owner-transition.json",
            &missing_transition,
            "generation transition requires an installed-owner signed authorization",
        )?;

        let owner_transition = fixture.generation_transition_authorization(
            requested_action,
            generation.clone(),
            revision,
            active.clone(),
            &assurance,
        );
        let wrong_owner = SignedAdmissionWire::sign(
            AdmissionKind::GenerationTransition,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.commissioner.clone(),
            owner_transition.payload,
            fixture.identities.commissioner_key(),
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-wrong-owner-transition.json",
            &ReferenceFixture::activation_request_with_transition(&assurance, &wrong_owner),
            "only the installed institution owner may authorize a generation transition",
        )?;

        let wrong_action = fixture.generation_transition_authorization(
            swapped_action,
            generation.clone(),
            revision,
            active.clone(),
            &assurance,
        );
        refuse(
            database_url,
            fixture,
            "lifecycle-swapped-action-transition.json",
            &ReferenceFixture::activation_request_with_transition(&assurance, &wrong_action),
            "signed lifecycle assurance control differs from owner transition action",
        )?;

        let wrong_target = fixture.generation_transition_authorization(
            requested_action,
            Digest::blake3(b"different signed generation target"),
            revision,
            active.clone(),
            &assurance,
        );
        refuse(
            database_url,
            fixture,
            "lifecycle-swapped-target-transition.json",
            &ReferenceFixture::activation_request_with_transition(&assurance, &wrong_target),
            "signed lifecycle assurance target differs from owner transition target",
        )?;

        let owner_transition = fixture.generation_transition_authorization(
            requested_action,
            generation.clone(),
            revision,
            active.clone(),
            &assurance,
        );
        let mut altered_assurance = assurance.clone();
        altered_assurance.run.payload.result = ControlResult::Violation;
        altered_assurance.run = SignedAdmissionWire::sign(
            AdmissionKind::ControlRun,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.control_producer.clone(),
            altered_assurance.run.payload,
            fixture.identities.control_producer_key(),
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-swapped-assurance-transition.json",
            &ReferenceFixture::activation_request_with_transition(
                &altered_assurance,
                &owner_transition,
            ),
            "owner generation transition assurance digest differs from supplied assurance",
        )?;

        // Every non-clean state reaches the real lifecycle boundary. A parse
        // failure or an unreachable detector cannot count as this witness.
        for result in ControlResult::all()
            .into_iter()
            .filter(|value| *value != ControlResult::Clean)
        {
            let mut altered = assurance.clone();
            altered.run.payload.result = result;
            altered.run = SignedAdmissionWire::sign(
                AdmissionKind::ControlRun,
                fixture.host_trust.workspace.institution.clone(),
                fixture.host_trust.workspace.id.clone(),
                fixture.identities.control_producer.clone(),
                altered.run.payload,
                fixture.identities.control_producer_key(),
            )?;
            refuse(
                database_url,
                fixture,
                "lifecycle-non-clean.json",
                &fixture.activation_request(kind, &generation, revision, active.as_ref(), &altered),
                "signed lifecycle assurance differs from freshly calibrated artifact validation",
            )?;
        }
        let mut wrong_grant = assurance.clone();
        wrong_grant.run.payload.authorization = Digest::blake3(b"another otherwise-adequate grant");
        wrong_grant.run = SignedAdmissionWire::sign(
            AdmissionKind::ControlRun,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.control_producer.clone(),
            wrong_grant.run.payload,
            fixture.identities.control_producer_key(),
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-substituted-grant.json",
            &fixture.activation_request(kind, &generation, revision, active.as_ref(), &wrong_grant),
            "control run authorization digest differs from its admitted direct grant",
        )?;
        let mut dangling = assurance.clone();
        dangling.proof.payload.retained_evidence = EvidenceId::new();
        dangling.proof = SignedAdmissionWire::sign(
            AdmissionKind::ActivationProof,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.verifier.clone(),
            dangling.proof.payload,
            fixture.identities.verifier_key(),
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-dangling-evidence.json",
            &fixture.activation_request(kind, &generation, revision, active.as_ref(), &dangling),
            "activation proof lacks exact verifier-signed lifecycle calibration evidence",
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-stale-revision.json",
            &fixture.activation_request(
                kind,
                &generation,
                revision - 1,
                active.as_ref(),
                &assurance,
            ),
            "generation activation compare-and-swap is stale",
        )?;

        // Give the producer an otherwise valid verification grant so this
        // failure establishes independence, rather than a missing permission.
        let mut self_grant = authorities.proof_authority.payload.clone();
        self_grant.id = DelegationId::new();
        self_grant.subject = fixture.identities.control_producer.clone();
        let self_grant = fixture.signed_commissioner_delegation(self_grant);
        submit_commissioning(
            database_url,
            fixture,
            "self-verifier-grant.json",
            &serde_json::json!({
                "kind": "admit_delegation", "delegation": self_grant,
            }),
        )?;
        let snapshot = status_value(database_url, fixture)?;
        let revision = snapshot["revision"]
            .as_i64()
            .ok_or("status omitted revision")?;
        let mut self_proof = assurance.clone();
        self_proof.proof_authority = self_grant;
        let self_report = validate(
            database_url,
            fixture,
            generation,
            &control,
            "self-calibration",
        )?;
        assert_eq!(self_report, producer);
        self_proof.calibration.payload.producer_delegation =
            self_proof.proof_authority.payload.id.clone();
        self_proof.calibration.payload.observed_at = Timestamp::now();
        self_proof.calibration = SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.control_producer.clone(),
            self_proof.calibration.payload,
            fixture.identities.control_producer_key(),
        )?;
        self_proof.proof.payload.proved_at = Timestamp::now();
        self_proof.proof = SignedAdmissionWire::sign(
            AdmissionKind::ActivationProof,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.control_producer.clone(),
            self_proof.proof.payload,
            fixture.identities.control_producer_key(),
        )?;
        self_proof.run.payload.started_at = Timestamp::now();
        assert_eq!(
            validate(database_url, fixture, generation, &control, "self-producer")?,
            producer
        );
        self_proof.run.payload.finished_at = Timestamp::now();
        self_proof.run = SignedAdmissionWire::sign(
            AdmissionKind::ControlRun,
            fixture.host_trust.workspace.institution.clone(),
            fixture.host_trust.workspace.id.clone(),
            fixture.identities.control_producer.clone(),
            self_proof.run.payload,
            fixture.identities.control_producer_key(),
        )?;
        refuse(
            database_url,
            fixture,
            "lifecycle-self-verification.json",
            &fixture.activation_request(kind, &generation, revision, active.as_ref(), &self_proof),
            "the control producer also signed its activation proof",
        )?;
    }
    let snapshot = status_value(database_url, fixture)?;
    let revision = snapshot["revision"]
        .as_i64()
        .ok_or("status omitted revision")?;
    let active = serde_json::from_value(snapshot["active_generation"].clone())?;
    submit_commissioning(
        database_url,
        fixture,
        &format!("{kind}-generation.json"),
        &fixture.activation_request(kind, &generation, revision, active.as_ref(), &assurance),
    )?;
    assert_eq!(
        status_value(database_url, fixture)?["active_generation"],
        serde_json::json!(generation)
    );
    let verified = submit_commissioning(
        database_url,
        fixture,
        "verify-after-activation.json",
        &serde_json::json!({
            "kind": "generation", "request": {"kind": "verify", "generation": generation},
        }),
    )?;
    assert_eq!(
        verified["verified"], true,
        "typed assurance rows preserve commissioning provenance"
    );
    Ok(())
}

/// Complete Stage 1 and Stage 2 once for an inactive candidate, then cache the
/// retained qualified proof for an exact future rollback.
fn qualify_candidate(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    generation: &Digest,
) -> TestResult<Vec<politeiad::service_operation::DetectorCalibrationEvidenceSubmission>> {
    let documents =
        operations.detector_qualification_documents(fixture, generation, Timestamp::now());
    for (index, authority) in documents.authority_admissions.iter().enumerate() {
        submit_commissioning(
            database_url,
            fixture,
            &format!("qualification-authority-{index}.json"),
            authority,
        )?;
    }
    let result = submit_commissioning(
        database_url,
        fixture,
        "exercise-detector-qualification.json",
        &documents.exercise,
    )?;
    let report: politeia_policy::operational::PublicDetectorCalibration =
        serde_json::from_value(result["report"].clone())?;
    let detector = report.control.clone();
    let qualification = operations.detector_calibration_evidence(fixture, report);
    submit_commissioning(
        database_url,
        fixture,
        "admit-detector-qualification.json",
        &serde_json::json!({
            "kind": "detector_calibration_evidence",
            "submission": qualification,
        }),
    )?;
    let attempts_before_replay = operation_attempt_counts(database_url, fixture)?;
    refuse(
        database_url,
        fixture,
        "replayed-detector-qualification.json",
        &documents.exercise,
        "replay",
    )?;
    assert_eq!(
        operation_attempt_counts(database_url, fixture)?,
        attempts_before_replay,
        "replaying Stage 1 must not create another candidate effect attempt or completion"
    );
    operations.remember_qualification(generation.clone(), detector, qualification);
    let qualifications = operations
        .qualifications_for(generation)
        .expect("completed Stage 2 retains candidate detector qualification");
    assert_eq!(
        qualifications.len(),
        operations.blocking_detector_ids().len(),
        "activation carries one retained proof for every blocking detector"
    );
    assert_eq!(
        operations.blocking_binding_count(),
        4,
        "the fixture retains all four enforced operation-scope bindings"
    );
    assert_eq!(
        qualifications.len(),
        1,
        "the fixture's four blocking bindings share one detector proof"
    );
    Ok(qualifications)
}

/// Read the same durable attempt/completion seam used by the package's
/// executable-identity witness. This observes the exact subject of the replay
/// refusal instead of treating a transport failure as proof of no execution.
fn operation_attempt_counts(
    database_url: &str,
    fixture: &ReferenceFixture,
) -> TestResult<(i64, i64)> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (client, connection) = runtime.block_on(tokio_postgres::connect(database_url, NoTls))?;
    let _connection = runtime.spawn(connection);
    let institution = fixture.host_trust.workspace.institution.0;
    let workspace = fixture.host_trust.workspace.id.0;
    let row = runtime.block_on(client.query_one(
        "SELECT COUNT(*)::BIGINT, COUNT(*) FILTER (WHERE status = 'completed')::BIGINT
         FROM operation_attempts
         WHERE institution_id = $1 AND workspace_id = $2",
        &[&institution, &workspace],
    ))?;
    Ok((row.get(0), row.get(1)))
}

fn validate(
    database_url: &str,
    fixture: &ReferenceFixture,
    generation: &Digest,
    control: &str,
    role: &str,
) -> TestResult<GenerationValidationReport> {
    let response = submit_commissioning(
        database_url,
        fixture,
        &format!("{role}-validation.json"),
        &serde_json::json!({
            "kind": "generation", "request": {"kind": "validate", "generation": generation, "control": control},
        }),
    )?;
    Ok(serde_json::from_value(response["validation"].clone())?)
}

fn refuse(
    database_url: &str,
    fixture: &ReferenceFixture,
    name: &str,
    document: &serde_json::Value,
    expected: &str,
) -> TestResult {
    let path = write_request(fixture, name, document)?;
    require_refusal(
        &run(
            database_url,
            &[
                std::path::Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &path,
            ],
        )?,
        name,
        expected,
    )
}
