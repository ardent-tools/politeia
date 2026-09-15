//! Process witness that an approved executable is the daemon that executes it.
//!
//! The fixture deliberately stages the public `politeia` CLI as the approved
//! deterministic executable while the socket daemon is `politeiad`. Its policy
//! and execution registry consistently name the staged CLI, so only the daemon
//! process-owned executable measurement can refuse the generation.

use std::{fs, path::Path};

use politeia_core::Digest;

use super::evidence::{observe_effects, record_observation};
use super::{
    OperationalFixture, ReferenceFixture, ReferenceInstitutionKind, TestResult, await_status,
    client_binary, commission_generation, daemon_binary, require_refusal, require_source_capture,
    require_success, run, serve, status_value, submit_commissioning, write_request,
};

const EXECUTABLE_IDENTITY_REFUSAL: &str =
    "approved executable component differs from the running daemon executable";

/// Exercise the daemon's process-owned executable identity check through the
/// public CLI and Unix socket.
///
/// This helper owns a fresh institution and installation so it can run beside
/// the package's two reference institutions without sharing a workspace. The
/// returned observation lets the parent acceptance record the exact refused
/// generation and unchanged active pointer.
pub(crate) fn exercise(database_url: &str) -> TestResult<serde_json::Value> {
    let mut fixture = ReferenceFixture::new(
        ReferenceInstitutionKind::SoftwareDevelopment,
        Path::new(client_binary()),
    );
    let operations = OperationalFixture::install(&mut fixture);
    let host_trust = fixture.write_host_trust();
    require_success(
        run(
            database_url,
            &[Path::new("initialize"), &fixture.prefix(), &host_trust],
        )?,
        "executable identity installation",
    )?;
    fixture.stage_generation_artifacts();
    let staged_digest = Digest::blake3(&fs::read(
        fixture
            .prefix()
            .join("workspace/generation/components/executable"),
    )?);
    let daemon_digest = Digest::blake3(&fs::read(daemon_binary())?);
    assert_ne!(
        staged_digest, daemon_digest,
        "the witness needs distinct public CLI and daemon executable images"
    );

    let daemon = serve(database_url, &fixture)?;
    let _ = await_status(database_url, &fixture)?;
    let (capture_delegation, prepared_capture) = fixture.bootstrap_capture_documents();
    submit_commissioning(
        database_url,
        &fixture,
        "executable-identity-capture-authority.json",
        &serde_json::json!({
            "kind": "admit_delegation",
            "delegation": fixture.signed_commissioner_delegation(capture_delegation),
        }),
    )?;
    let capture = fixture.capture_after_admission(&prepared_capture);
    fs::copy(
        &fixture.source_document,
        fixture.prefix().join("workspace/institution.md"),
    )?;
    let capture_request = write_request(
        &fixture,
        "executable-identity-capture.json",
        &capture.document,
    )?;
    require_source_capture(
        run(
            database_url,
            &[
                Path::new("snapshot"),
                &fixture.prefix().join("run/politeiad.sock"),
                &capture_request,
            ],
        )?,
        "executable identity source capture",
    )?;

    let commissioned = commission_generation(database_url, &fixture, &capture)?;
    let validation = write_request(
        &fixture,
        "executable-identity-validate.json",
        &serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "validate",
                "generation": commissioned.generation,
                "control": "generation:activate",
            },
        }),
    )?;
    let effects_before_validation = observe_effects(database_url, &fixture)?;
    require_refusal(
        &run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &validation,
            ],
        )?,
        "generation validation with a staged CLI executable",
        EXECUTABLE_IDENTITY_REFUSAL,
    )?;
    let effects_after_validation = observe_effects(database_url, &fixture)?;
    record_observation(
        "executable_identity_validation_effects",
        &serde_json::json!({
            "before": effects_before_validation,
            "after": effects_after_validation,
        }),
    )?;
    assert_eq!(
        effects_after_validation, effects_before_validation,
        "generation validation with a staged executable creates no attempt, completion, or outbox record"
    );

    // The first capability submission has executable claims and reaches the
    // same process-bound check. Admit only its prerequisite direct grants;
    // success of those grants cannot activate a generation or create an effect.
    let mut capability_refused = false;
    for (index, request) in operations.admission_requests().iter().enumerate() {
        if request["kind"] == "capability_evidence" {
            let path = write_request(
                &fixture,
                &format!("executable-identity-capability-{index}.json"),
                request,
            )?;
            let effects_before_capability = observe_effects(database_url, &fixture)?;
            require_refusal(
                &run(
                    database_url,
                    &[
                        Path::new("commissioning"),
                        &fixture.prefix().join("run/politeiad.sock"),
                        &path,
                    ],
                )?,
                "capability evidence with a staged CLI executable",
                EXECUTABLE_IDENTITY_REFUSAL,
            )?;
            let effects_after_capability = observe_effects(database_url, &fixture)?;
            record_observation(
                "executable_identity_capability_effects",
                &serde_json::json!({
                    "before": effects_before_capability,
                    "after": effects_after_capability,
                }),
            )?;
            assert_eq!(
                effects_after_capability, effects_before_capability,
                "capability evidence with a staged executable creates no attempt, completion, or outbox record"
            );
            capability_refused = true;
            break;
        }
        submit_commissioning(
            database_url,
            &fixture,
            &format!("executable-identity-prerequisite-{index}.json"),
            request,
        )?;
    }
    assert!(
        capability_refused,
        "operational fixture must expose signed executable capability evidence"
    );

    let status = status_value(database_url, &fixture)?;
    let active: Option<Digest> = serde_json::from_value(status["active_generation"].clone())?;
    assert!(
        active.is_none(),
        "executable identity refusal leaves the active generation pointer empty"
    );
    let effects = observe_effects(database_url, &fixture)?;
    drop(daemon);

    Ok(serde_json::json!({
        "institution": fixture.host_trust.workspace.institution,
        "workspace": fixture.host_trust.workspace.id,
        "generation": commissioned.generation,
        "staged_executable_digest": staged_digest,
        "running_daemon_digest": daemon_digest,
        "active_generation": active,
        "effects": effects,
        "refusal": EXECUTABLE_IDENTITY_REFUSAL,
    }))
}
