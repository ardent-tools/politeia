//! Active institutional-learning exercise over the installed daemon socket.
//!
//! Every state transition below is a signed file sent to the public CLI. The
//! process test never opens a storage handle or constructs a coordinator.

use std::{collections::BTreeSet, fs, path::Path};

use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, PrincipalId,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assessment::{AssessmentRelation, RelationKind, SUPERSEDE_ACTION};
use politeia_policy::bootstrap::bootstrap_capture_resources;
use politeiad::{
    service::{SourceCaptureSubmission, capture_operation_input_digest},
    service_learning::LearningRequest,
    service_operation::{
        CAPTURE_SOURCE_OPERATION, COMPILE_CONTEXT_OPERATION, DISCOVER_CAPABILITIES_OPERATION,
        OperationSubmission,
    },
};

use crate::package_support::{
    CandidateDocuments, CaptureDocuments, LearningSourceDocuments, ReferenceFixture,
    learning::{active_learning_budget, active_learning_effects},
    operational::OperationalFixture,
};

use super::{
    TestResult,
    evidence::{observe_effects, state_entry_exists},
    require_coordinated, require_refusal, run, submit_commissioning, write_request,
};

pub(super) struct LearningExercise {
    pub(super) temporary_grants: Vec<Delegation>,
    pub(super) completion: serde_json::Value,
    pub(super) durable_completion: serde_json::Value,
    pub(super) historical_context: serde_json::Value,
    pub(super) historical_context_receipt: serde_json::Value,
    pub(super) historical_approval: serde_json::Value,
}

/// Exercise active context, discovery, feedback, source correction, and the
/// resulting current projection through the real daemon and CLI.
#[expect(
    clippy::too_many_arguments,
    reason = "the process witness keeps each externally admitted provenance input explicit"
)]
pub(crate) fn exercise(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    generation: &Digest,
    original_source: &LearningSourceDocuments,
    original_candidate: &CandidateDocuments,
    original_capture: &CaptureDocuments,
) -> TestResult<LearningExercise> {
    let runtime = politeia_core::RuntimeGenerationId::from_digest(generation.clone());
    let now = Timestamp::now();

    let context_grant = learning_grant(
        fixture,
        fixture.identities.worker.clone(),
        BTreeSet::from([politeiad::learning::COMPILE_CONTEXT_ACTION.to_owned()]),
        context_resources(fixture, &original_source.source),
        now,
    );
    let discovery_grant = learning_grant(
        fixture,
        fixture.identities.worker.clone(),
        BTreeSet::from([politeiad::learning::DISCOVER_CAPABILITIES_ACTION.to_owned()]),
        workspace_resources(fixture),
        now,
    );
    let feedback_grant = learning_grant(
        fixture,
        fixture.identities.worker.clone(),
        BTreeSet::from([politeiad::learning::RECORD_FEEDBACK_ACTION.to_owned()]),
        context_resources(fixture, &original_source.source),
        now,
    );
    for (name, grant) in [
        ("active-context-grant.json", &context_grant),
        ("active-discovery-grant.json", &discovery_grant),
        ("active-feedback-grant.json", &feedback_grant),
    ] {
        submit_commissioning(
            database_url,
            fixture,
            name,
            &delegation_admission(fixture, grant.clone()),
        )?;
    }

    let context = fixture.active_context_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &context_grant,
        runtime.clone(),
        original_source,
        original_candidate,
    );
    let context_submission = operations.submission(
        fixture,
        COMPILE_CONTEXT_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        context.input_digest().clone(),
        vec![context_grant.clone()],
        context.resources().clone(),
        active_learning_budget(),
        now,
        Some(context.idempotency_key()),
    );
    let alternate_context = fixture.active_context_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &context_grant,
        runtime.clone(),
        original_source,
        original_candidate,
    );
    let alternate_context_submission = operations.submission(
        fixture,
        COMPILE_CONTEXT_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        alternate_context.input_digest().clone(),
        vec![context_grant.clone()],
        alternate_context.resources().clone(),
        active_learning_budget(),
        Timestamp::now(),
        Some(alternate_context.idempotency_key()),
    );
    let context_document = context.document(context_submission);
    refuse_learning_assurance(
        database_url,
        fixture,
        "active-context",
        &context_document,
        signed_control_run(&alternate_context_submission)?,
    )?;
    let original_context = submit_commissioning(
        database_url,
        fixture,
        "active-context.json",
        &context_document,
    )?;
    let prior_context_receipt =
        super::continuity::observe_completed_disclosure(database_url, fixture, &original_context)?;
    assert_disclosure_decision(
        operations,
        COMPILE_CONTEXT_OPERATION,
        &context_document,
        &prior_context_receipt,
    )?;
    assert_eq!(
        original_context["context"]["input_ids"],
        serde_json::json!([original_source.source]),
        "active context selects exactly the approved source"
    );
    let prior_bytes: Vec<u8> = serde_json::from_value(
        original_context["content"][original_source.source.0.to_string()].clone(),
    )?;
    assert_eq!(prior_bytes, fs::read(&fixture.source_document)?);
    require_refusal(
        &commissioning(
            database_url,
            fixture,
            "active-context-replay.json",
            &context_document,
        )?,
        "active context replay",
        "replay",
    )?;

    let discovery = fixture.active_discovery_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &discovery_grant,
        runtime.clone(),
        &operations.capability_population_digest(),
    );
    let discovery_submission = operations.submission(
        fixture,
        DISCOVER_CAPABILITIES_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        discovery.input_digest().clone(),
        vec![discovery_grant.clone()],
        discovery.resources().clone(),
        active_learning_budget(),
        now,
        Some(discovery.idempotency_key()),
    );
    let alternate_discovery = fixture.active_discovery_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &discovery_grant,
        runtime.clone(),
        &operations.capability_population_digest(),
    );
    let alternate_discovery_submission = operations.submission(
        fixture,
        DISCOVER_CAPABILITIES_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        alternate_discovery.input_digest().clone(),
        vec![discovery_grant.clone()],
        alternate_discovery.resources().clone(),
        active_learning_budget(),
        Timestamp::now(),
        Some(alternate_discovery.idempotency_key()),
    );
    let discovery_document = discovery.document(discovery_submission);
    refuse_learning_assurance(
        database_url,
        fixture,
        "active-discovery",
        &discovery_document,
        signed_control_run(&alternate_discovery_submission)?,
    )?;
    let discovery_result = submit_commissioning(
        database_url,
        fixture,
        "active-discovery.json",
        &discovery_document,
    )?;
    let discovery_receipt =
        super::continuity::observe_completed_disclosure(database_url, fixture, &discovery_result)?;
    assert_disclosure_decision(
        operations,
        DISCOVER_CAPABILITIES_OPERATION,
        &discovery_document,
        &discovery_receipt,
    )?;
    assert_eq!(
        discovery_result["operations"],
        serde_json::to_value(operations.operation_ids())?,
        "active discovery reports only the generation registry operation identities"
    );
    assert_eq!(
        discovery_result["resources"],
        serde_json::to_value(operations.resource_ids())?,
        "active discovery reports only the generation registry resource identities"
    );

    // A separately signed operation with an otherwise valid route/control set
    // must still fail before disclosure when it binds another primary input.
    let substituted = fixture.active_context_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &context_grant,
        runtime.clone(),
        original_source,
        original_candidate,
    );
    let substituted_submission = operations.submission(
        fixture,
        COMPILE_CONTEXT_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        Digest::blake3(b"substituted active learning input"),
        vec![context_grant.clone()],
        substituted.resources().clone(),
        active_learning_budget(),
        now,
        Some(substituted.idempotency_key()),
    );
    require_refusal(
        &commissioning(
            database_url,
            fixture,
            "active-context-input-substitution.json",
            &substituted.document(substituted_submission),
        )?,
        "active context input substitution",
        "input does not bind the signed request and selected population",
    )?;

    let feedback = fixture.feedback_documents(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &feedback_grant,
        runtime.clone(),
        original_source,
        original_capture,
        Digest::blake3(b"package process feedback: original source needs correction"),
    );
    let feedback_result = submit_commissioning(
        database_url,
        fixture,
        "active-feedback.json",
        &feedback.document,
    )?;
    assert_eq!(
        feedback_result["proposal"]["source"],
        serde_json::json!(original_source.source),
        "feedback is retained as an inert proposal over the exact original source"
    );

    let replacement_bytes = replacement_source_bytes(&prior_bytes);
    fs::write(&fixture.source_document, &replacement_bytes)?;
    fs::copy(
        &fixture.source_document,
        fixture.prefix().join("workspace/institution.md"),
    )?;
    let (capture_grant, capture_documents) = fixture.bootstrap_capture_documents();
    submit_commissioning(
        database_url,
        fixture,
        "corrected-source-capture-grant.json",
        &delegation_admission(fixture, capture_grant.clone()),
    )?;
    let capture_documents = fixture.capture_after_admission(&capture_documents);
    let replacement_capture =
        active_capture_document(fixture, operations, &capture_grant, capture_documents, now)?;
    let capture_submission: SourceCaptureSubmission =
        serde_json::from_value(replacement_capture.document.clone())?;
    let capture_state_key = format!("source_capture:{}", capture_submission.capture.payload.id.0);
    assert!(
        !state_entry_exists(database_url, fixture, &capture_state_key)?,
        "the fresh active capture has no durable source artifact before dispatcher admission"
    );
    let alternate_capture_submission = operations.submission(
        fixture,
        CAPTURE_SOURCE_OPERATION,
        &fixture.identities.commissioner,
        fixture.identities.commissioner_key(),
        Digest::blake3(b"another signed capture operation intent"),
        vec![capture_grant.clone()],
        bootstrap_capture_resources(&capture_submission.capture.payload),
        capture_grant.budget.clone(),
        Timestamp::now(),
        None,
    );
    refuse_capture_assurance(
        database_url,
        fixture,
        &replacement_capture.document,
        signed_control_run(&alternate_capture_submission)?,
        &capture_state_key,
    )?;
    let replacement_capture_result = require_coordinated(
        run(
            database_url,
            &[
                Path::new("snapshot"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(
                    fixture,
                    "corrected-active-capture.json",
                    &replacement_capture.document,
                )?,
            ],
        )?,
        "active corrected source capture",
    )?;
    assert!(replacement_capture_result["snapshot_manifest"].is_string());
    assert!(
        state_entry_exists(database_url, fixture, &capture_state_key)?,
        "the accepted active capture retains its governed source artifact"
    );
    let replacement_candidate = fixture.candidate_documents(&capture_grant, &replacement_capture);
    let approval_key = format!(
        "fact_approval:{}",
        original_candidate.approval.payload.claim.0
    );
    let prior_approval =
        super::continuity::observe_signed_state(database_url, fixture, &approval_key)?;
    submit_commissioning(
        database_url,
        fixture,
        "corrected-source-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": replacement_candidate.candidate.clone(),
            "approval": replacement_candidate.approval.clone(),
        }),
    )?;
    let mut replacement_source =
        fixture.learning_source_documents(&replacement_capture, &replacement_candidate);
    lower_source_relevance(fixture, &mut replacement_source, 1)?;
    submit_commissioning(
        database_url,
        fixture,
        "corrected-learning-source.json",
        &replacement_source.document,
    )?;

    // Both canonical sources are still eligible here. The original deliberately
    // outranks the successor, so this context proves that a later change cannot
    // be attributed to grant narrowing or incidental ranking.
    let broad_context_grant = learning_grant(
        fixture,
        fixture.identities.worker.clone(),
        BTreeSet::from([politeiad::learning::COMPILE_CONTEXT_ACTION.to_owned()]),
        BTreeSet::from([
            politeiad::learning::context_workspace_resource(&fixture.host_trust.workspace.id),
            politeiad::learning::context_source_resource(
                &fixture.host_trust.workspace.id,
                &original_source.source,
            ),
            politeiad::learning::context_source_resource(
                &fixture.host_trust.workspace.id,
                &replacement_source.source,
            ),
        ]),
        Timestamp::now(),
    );
    submit_commissioning(
        database_url,
        fixture,
        "both-sources-context-grant.json",
        &delegation_admission(fixture, broad_context_grant.clone()),
    )?;
    let before_correction = fixture.active_context_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &broad_context_grant,
        runtime.clone(),
        original_source,
        original_candidate,
    );
    let before_correction_submission = operations.submission(
        fixture,
        COMPILE_CONTEXT_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        before_correction.input_digest().clone(),
        vec![broad_context_grant.clone()],
        before_correction.resources().clone(),
        active_learning_budget(),
        Timestamp::now(),
        Some(before_correction.idempotency_key()),
    );
    let before_correction_result = submit_commissioning(
        database_url,
        fixture,
        "both-sources-before-correction.json",
        &before_correction.document(before_correction_submission),
    )?;
    assert_eq!(
        before_correction_result["context"]["input_ids"],
        serde_json::json!([original_source.source]),
        "without a correction the higher-relevance original remains current"
    );

    let correction_grant = owner_correction_grant(fixture, now);
    submit_commissioning(
        database_url,
        fixture,
        "owner-correction-grant.json",
        &delegation_admission(fixture, correction_grant.clone()),
    )?;
    let relation = AssessmentRelation {
        id: EvidenceId::new(),
        kind: RelationKind::Supersession,
        prior: original_source.source.clone(),
        successor: replacement_source.source.clone(),
        authority: fixture.identities.owner.clone(),
        authority_delegation: correction_grant.id.clone(),
        asserted_at: Timestamp::now(),
    };
    let correction = fixture.approved_correction_document(
        &correction_grant,
        feedback.id,
        original_candidate.candidate.payload.subject.clone(),
        relation.clone(),
    );
    require_refusal(
        &commissioning(
            database_url,
            fixture,
            "owner-correction-unknown-feedback.json",
            &fixture.approved_correction_document(
                &correction_grant,
                politeia_core::CommissioningRecordId::new(),
                original_candidate.candidate.payload.subject.clone(),
                relation,
            ),
        )?,
        "owner correction requires persisted feedback",
        "correction feedback is not durably admitted",
    )?;
    submit_commissioning(
        database_url,
        fixture,
        "owner-approved-source-correction.json",
        &correction,
    )?;

    let replacement_context = fixture.active_context_draft(
        fixture.identities.worker.clone(),
        fixture.identities.worker_key(),
        &broad_context_grant,
        runtime,
        &replacement_source,
        &replacement_candidate,
    );
    let replacement_submission = operations.submission(
        fixture,
        COMPILE_CONTEXT_OPERATION,
        &fixture.identities.worker,
        fixture.identities.worker_key(),
        replacement_context.input_digest().clone(),
        vec![broad_context_grant.clone()],
        replacement_context.resources().clone(),
        active_learning_budget(),
        Timestamp::now(),
        Some(replacement_context.idempotency_key()),
    );
    let replacement_result = submit_commissioning(
        database_url,
        fixture,
        "corrected-active-context.json",
        &replacement_context.document(replacement_submission),
    )?;
    assert_eq!(
        replacement_result["context"]["input_ids"],
        serde_json::json!([replacement_source.source]),
        "the current projection selects the owner-approved successor"
    );
    let disclosed_replacement: Vec<u8> = serde_json::from_value(
        replacement_result["content"][replacement_source.source.0.to_string()].clone(),
    )?;
    assert_eq!(disclosed_replacement, replacement_bytes);
    let preserved_context_receipt =
        super::continuity::observe_completed_disclosure(database_url, fixture, &original_context)?;
    assert_eq!(
        prior_context_receipt, preserved_context_receipt,
        "correction preserves the exact delivered context receipt"
    );
    let preserved_approval =
        super::continuity::observe_signed_state(database_url, fixture, &approval_key)?;
    assert_eq!(
        prior_approval, preserved_approval,
        "correction preserves the original signed approval bytes in durable state"
    );
    super::evidence::record_observation("preserved_approval", &preserved_approval)?;
    super::evidence::record_observation("preserved_context_receipt", &preserved_context_receipt)?;
    let durable_completion = super::continuity::observe_completed_disclosure(
        database_url,
        fixture,
        &replacement_result,
    )?;
    super::evidence::record_observation("corrected_context_completion", &durable_completion)?;
    // Root revokes this temporary commissioner authority during the handoff
    // witness. Worker, owner, producer, and verifier grants remain live so
    // their distinct durable records can be tested separately.
    Ok(LearningExercise {
        temporary_grants: vec![capture_grant],
        completion: replacement_result["completion"].clone(),
        durable_completion,
        historical_context: original_context,
        historical_context_receipt: preserved_context_receipt,
        historical_approval: preserved_approval,
    })
}

fn commissioning(
    database_url: &str,
    fixture: &ReferenceFixture,
    name: &str,
    document: &serde_json::Value,
) -> TestResult<std::process::Output> {
    let path = write_request(fixture, name, document)?;
    run(
        database_url,
        &[
            Path::new("commissioning"),
            &fixture.prefix().join("run/politeiad.sock"),
            &path,
        ],
    )
}

fn learning_grant(
    fixture: &ReferenceFixture,
    subject: PrincipalId,
    actions: BTreeSet<String>,
    resources: BTreeSet<String>,
    at: Timestamp,
) -> Delegation {
    // Leave room for repeated legitimate disclosures and a replay attempt.
    // A spent one-call budget must not substitute for replay protection.
    let mut budget = active_learning_budget();
    for cap in [
        &mut budget.wall_ms,
        &mut budget.cpu_ms,
        &mut budget.memory_bytes,
        &mut budget.io_bytes,
        &mut budget.network_bytes,
        &mut budget.external_cost_microunits,
    ] {
        *cap = cap.map(|value| {
            value
                .checked_mul(4)
                .expect("fixture budget has room for four requests")
        });
    }
    Delegation {
        id: DelegationId::new(),
        issuer: fixture.identities.owner.clone(),
        subject,
        parent: None,
        actions,
        resources,
        effects: active_learning_effects(),
        data_classes: BTreeSet::from([DataClass::Internal]),
        audience: BTreeSet::from(["commissioning".to_owned()]),
        expires_at: at + SignedDuration::from_hours(1),
        budget,
    }
}

fn owner_correction_grant(fixture: &ReferenceFixture, at: Timestamp) -> Delegation {
    Delegation {
        id: DelegationId::new(),
        issuer: fixture.identities.owner.clone(),
        subject: fixture.identities.owner.clone(),
        parent: None,
        actions: BTreeSet::from([SUPERSEDE_ACTION.to_owned()]),
        resources: BTreeSet::from(["assessment:source-correction".to_owned()]),
        effects: BTreeSet::from([Effect::ReadInstitutionalContext]),
        data_classes: BTreeSet::from([DataClass::Internal]),
        audience: BTreeSet::from(["commissioning".to_owned()]),
        expires_at: at + SignedDuration::from_hours(1),
        budget: active_learning_budget(),
    }
}

fn context_resources(fixture: &ReferenceFixture, source: &EvidenceId) -> BTreeSet<String> {
    BTreeSet::from([
        politeiad::learning::context_workspace_resource(&fixture.host_trust.workspace.id),
        politeiad::learning::context_source_resource(&fixture.host_trust.workspace.id, source),
    ])
}

fn workspace_resources(fixture: &ReferenceFixture) -> BTreeSet<String> {
    BTreeSet::from([politeiad::learning::context_workspace_resource(
        &fixture.host_trust.workspace.id,
    )])
}

fn delegation_admission(fixture: &ReferenceFixture, delegation: Delegation) -> serde_json::Value {
    serde_json::json!({
        "kind": "admit_delegation",
        "delegation": fixture.signed_commissioner_delegation(delegation),
    })
}

/// Extract a separately signed, correctly typed run that can be transplanted
/// into another request. The later refusal must therefore reach policy's exact
/// subject comparison rather than stopping at JSON decoding or signature
/// admission.
fn signed_control_run(submission: &OperationSubmission) -> TestResult<serde_json::Value> {
    Ok(serde_json::to_value(
        submission
            .assurance
            .first()
            .ok_or("native operation omitted its control assurance")?
            .run
            .clone(),
    )?)
}

/// Exercise both assurance failures through the actual learning ingress for a
/// context or discovery request. These documents retain valid primary request
/// and delegation axes; only operational assurance is omitted or replaced by
/// a correctly signed run from another exact intent.
fn refuse_learning_assurance(
    database_url: &str,
    fixture: &ReferenceFixture,
    label: &str,
    document: &serde_json::Value,
    alternate_run: serde_json::Value,
) -> TestResult {
    let before = observe_effects(database_url, fixture)?;
    let mut omitted = document.clone();
    *omitted
        .pointer_mut("/request/active_submission/assurance")
        .ok_or("learning request omitted active assurance")? = serde_json::json!([]);
    require_refusal(
        &commissioning(
            database_url,
            fixture,
            &format!("{label}-omitted-assurance.json"),
            &omitted,
        )?,
        &format!("{label} omitted assurance"),
        "operation assurance does not exactly cover active policy controls",
    )?;
    assert_eq!(
        observe_effects(database_url, fixture)?,
        before,
        "omitted learning assurance creates no attempt/reservation, completion, or outbox record"
    );

    let mut substituted = document.clone();
    *substituted
        .pointer_mut("/request/active_submission/assurance/0/run")
        .ok_or("learning request omitted active control run")? = alternate_run;
    require_refusal(
        &commissioning(
            database_url,
            fixture,
            &format!("{label}-substituted-run.json"),
            &substituted,
        )?,
        &format!("{label} substituted control run"),
        "mismatches Input",
    )?;
    assert_eq!(
        observe_effects(database_url, fixture)?,
        before,
        "substituted learning assurance creates no attempt/reservation, completion, or outbox record"
    );
    Ok(())
}

/// Confirm the daemon-retained disclosure receipt, not merely the generated
/// request, binds the evaluator's applicable binding and the exact fresh run
/// and shared activation proof supplied to the native handler.
fn assert_disclosure_decision(
    operations: &OperationalFixture,
    operation: &str,
    document: &serde_json::Value,
    durable: &serde_json::Value,
) -> TestResult {
    let decision = &durable["receipt"]["decision"];
    let expected_bindings = serde_json::to_value(operations.blocking_binding_ids_for(operation))?;
    let run = document
        .pointer("/request/active_submission/assurance/0/run/payload/id")
        .cloned()
        .ok_or("learning request omitted signed control-run identity")?;
    let proof = document
        .pointer("/request/active_submission/assurance/0/activation/payload/id")
        .cloned()
        .ok_or("learning request omitted signed activation-proof identity")?;
    assert_eq!(decision["allowed"], true);
    assert_eq!(
        decision["binding_ids"], expected_bindings,
        "durable learning decision retains every applicable policy binding"
    );
    assert_eq!(
        decision["control_runs"],
        serde_json::json!([run]),
        "durable learning decision retains the exact submitted control run"
    );
    assert_eq!(
        decision["activation_proofs"],
        serde_json::json!([proof]),
        "durable learning decision retains the shared detector activation proof"
    );
    Ok(())
}

/// Source capture uses the public snapshot entrypoint but reaches the same
/// active operational admission. Its source artifact must remain absent when
/// either assurance axis fails.
fn refuse_capture_assurance(
    database_url: &str,
    fixture: &ReferenceFixture,
    document: &serde_json::Value,
    alternate_run: serde_json::Value,
    capture_state_key: &str,
) -> TestResult {
    let before = observe_effects(database_url, fixture)?;
    let mut omitted = document.clone();
    *omitted
        .pointer_mut("/operation/assurance")
        .ok_or("active capture omitted assurance")? = serde_json::json!([]);
    require_refusal(
        &run(
            database_url,
            &[
                Path::new("snapshot"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(fixture, "active-capture-omitted-assurance.json", &omitted)?,
            ],
        )?,
        "active capture omitted assurance",
        "operation assurance does not exactly cover active policy controls",
    )?;
    assert_eq!(observe_effects(database_url, fixture)?, before);
    assert!(
        !state_entry_exists(database_url, fixture, capture_state_key)?,
        "omitted capture assurance does not retain a source artifact"
    );

    let mut substituted = document.clone();
    *substituted
        .pointer_mut("/operation/assurance/0/run")
        .ok_or("active capture omitted control run")? = alternate_run;
    require_refusal(
        &run(
            database_url,
            &[
                Path::new("snapshot"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(fixture, "active-capture-substituted-run.json", &substituted)?,
            ],
        )?,
        "active capture substituted control run",
        "mismatches Input",
    )?;
    assert_eq!(observe_effects(database_url, fixture)?, before);
    assert!(
        !state_entry_exists(database_url, fixture, capture_state_key)?,
        "substituted capture assurance does not retain a source artifact"
    );
    Ok(())
}

fn active_capture_document(
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    capture_grant: &Delegation,
    mut capture: CaptureDocuments,
    at: Timestamp,
) -> TestResult<CaptureDocuments> {
    let submission: SourceCaptureSubmission = serde_json::from_value(capture.document.clone())?;
    let input_digest = capture_operation_input_digest(&submission)?;
    let resources = bootstrap_capture_resources(&submission.capture.payload);
    let operation = operations.submission(
        fixture,
        CAPTURE_SOURCE_OPERATION,
        &fixture.identities.commissioner,
        fixture.identities.commissioner_key(),
        input_digest,
        vec![capture_grant.clone()],
        resources,
        capture_grant.budget.clone(),
        at,
        None,
    );
    let mut document = capture
        .document
        .as_object()
        .cloned()
        .ok_or("capture document is not an object")?;
    document.insert("operation".to_owned(), serde_json::to_value(operation)?);
    capture.document = serde_json::Value::Object(document);
    Ok(capture)
}

fn replacement_source_bytes(prior: &[u8]) -> Vec<u8> {
    let mut replacement = prior.to_vec();
    replacement
        .extend_from_slice(b"\n\nCorrected by the owner-approved active learning process.\n");
    replacement
}

fn lower_source_relevance(
    fixture: &ReferenceFixture,
    source: &mut LearningSourceDocuments,
    relevance: u32,
) -> TestResult {
    let request: LearningRequest = serde_json::from_value(source.document["request"].clone())?;
    let LearningRequest::RegisterSource { source: wire } = request else {
        return Err("replacement learning source document has the wrong request kind".into());
    };
    let mut payload = wire.payload;
    payload.relevance = relevance;
    let signed = SignedAdmissionWire::sign(
        AdmissionKind::LearningSource,
        fixture.host_trust.workspace.institution.clone(),
        fixture.host_trust.workspace.id.clone(),
        fixture.identities.owner.clone(),
        payload,
        fixture.identities.owner_key(),
    )?;
    source.document = serde_json::json!({
        "kind": "learning",
        "request": LearningRequest::RegisterSource { source: signed },
    });
    Ok(())
}
