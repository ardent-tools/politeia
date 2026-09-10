//! Executable substrate acceptance for two disjoint synthetic institutions.
//!
//! The test starts the compiled administrative CLI and daemon against the same
//! disposable PostgreSQL service used by the durable-storage acceptance tests.
//! It intentionally crosses only process and Unix-socket boundaries: raw
//! fixture documents are written to disk, and no service/coordinator/storage
//! object is constructed in this process.

#![expect(
    clippy::expect_used,
    reason = "acceptance fixtures must fail loudly when a process or response violates its contract"
)]

#[path = "package_support/mod.rs"]
mod package_support;

use std::{
    error::Error,
    fs,
    path::Path,
    process::{Child, Command, Output},
    thread,
    time::{Duration, Instant},
};

use package_support::{ReferenceFixture, ReferenceInstitutionKind};
use politeiad::transport::{LocalOutcome, LocalResponse};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn database_url() -> TestResult<String> {
    Ok(std::env::var("POLITEIA_STORAGE_TEST_DATABASE_URL")?)
}

fn client_binary() -> &'static str {
    env!("CARGO_BIN_EXE_politeia")
}

fn daemon_binary() -> &'static str {
    env!("CARGO_BIN_EXE_politeiad")
}

fn command(database_url: &str, arguments: &[&Path]) -> Command {
    let mut command = Command::new(client_binary());
    command.env("POLITEIA_DATABASE_URL", database_url);
    for argument in arguments {
        command.arg(argument);
    }
    command
}

fn run(database_url: &str, arguments: &[&Path]) -> TestResult<Output> {
    Ok(command(database_url, arguments).output()?)
}

fn require_success(output: Output, phase: &str) -> TestResult<String> {
    if output.status.success() {
        return Ok(String::from_utf8(output.stdout)?);
    }
    Err(format!(
        "{phase} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_request(
    fixture: &ReferenceFixture,
    name: &str,
    value: &serde_json::Value,
) -> TestResult<std::path::PathBuf> {
    let path = fixture.root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)?;
    Ok(path)
}

fn require_coordinated(output: Output, phase: &str) -> TestResult<serde_json::Value> {
    let response: LocalResponse = serde_json::from_str(&require_success(output, phase)?)?;
    let LocalOutcome::Ok {
        result: politeiad::OperationResult::Coordinated { result, .. },
    } = response.outcome
    else {
        return Err(format!("{phase} did not return a coordinated result").into());
    };
    Ok(result)
}

fn require_source_capture(output: Output, phase: &str) -> TestResult<serde_json::Value> {
    let response: LocalResponse = serde_json::from_str(&require_success(output, phase)?)?;
    match response.outcome {
        LocalOutcome::Ok {
            result: politeiad::OperationResult::Coordinated { result, .. },
        } => Ok(result),
        outcome => {
            Err(format!("{phase} did not return a mediated source capture: {outcome:?}").into())
        }
    }
}

fn serve(database_url: &str, fixture: &ReferenceFixture) -> TestResult<Daemon> {
    let mut command = Command::new(daemon_binary());
    command
        .env("POLITEIA_DATABASE_URL", database_url)
        .arg("serve")
        .arg(fixture.prefix());
    Ok(Daemon(command.spawn()?))
}

fn await_status(database_url: &str, fixture: &ReferenceFixture) -> TestResult<LocalResponse> {
    let socket = fixture.prefix().join("run/politeiad.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        let output = run(database_url, &[Path::new("status"), &socket])?;
        if output.status.success() {
            return Ok(serde_json::from_slice(&output.stdout)?);
        }
        last_error = String::from_utf8_lossy(&output.stderr).to_string();
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("daemon did not serve status within ten seconds: {last_error}").into())
}

fn stop(mut daemon: Daemon) -> TestResult {
    daemon.0.kill()?;
    daemon.0.wait()?;
    Ok(())
}

/// Stage every byte required by an operational generation before any daemon
/// call. This proves only the public source artifact inventory; publication
/// remains in the process acceptance below and requires a daemon-derived
/// commissioning record.
#[test]
fn staged_generation_inputs_bind_complete_public_artifacts() -> TestResult {
    let fixture = ReferenceFixture::new(
        ReferenceInstitutionKind::SoftwareDevelopment,
        Path::new(daemon_binary()),
    );
    fs::create_dir_all(fixture.prefix().join("workspace"))?;
    fixture.stage_generation_artifacts();
    let generation = fixture.prefix().join("workspace/generation");
    for path in [
        "public-source.tar",
        "policy/constitution.md",
        "specializer/artifacts.rs",
        "toolchain/rust-toolchain.toml",
        "schemas/semantic-operation.schema.json",
        "adapters/source.rs",
        "packs/reference-institution.md",
        "components/executable",
        "components/migrations.tar",
        "components/execution_registry.rs",
        "components/projections.json",
        "components/compatibility.md",
        "components/sbom.cargo-metadata.json",
        "components/provenance.json",
        "components/update-metadata.cargo-lock",
    ] {
        assert!(generation.join(path).is_file(), "staged {path}");
    }
    assert_eq!(
        fixture
            .host_trust
            .workspace
            .approved_generation
            .component_digests
            .len(),
        8,
        "the generation plan names every mandatory component role"
    );
    Ok(())
}

/// Prove two fresh local installations do not share identity or active state.
///
/// This is deliberately an ignored integration test because PostgreSQL is an
/// external dependency. It is run explicitly with the same configured or
/// disposable database command as the storage acceptance suite; it never
/// treats an absent database as a pass.
#[test]
#[ignore = "requires POLITEIA_STORAGE_TEST_DATABASE_URL and a disposable PostgreSQL instance"]
fn two_institution_installations_start_disjoint_daemons() -> TestResult {
    let database_url = database_url()?;
    assert_ne!(client_binary(), daemon_binary());
    let executable = Path::new(daemon_binary());
    let software = ReferenceFixture::new(ReferenceInstitutionKind::SoftwareDevelopment, executable);
    let analytics = ReferenceFixture::new(ReferenceInstitutionKind::Analytics, executable);
    assert_ne!(software.kind.directory(), analytics.kind.directory());
    assert_ne!(
        fs::read(&software.source_document)?,
        fs::read(&analytics.source_document)?,
        "the reference institutions must expose distinct synthetic source facts"
    );
    assert_ne!(software.identities.owner, software.identities.commissioner);
    assert_ne!(
        analytics.identities.owner,
        analytics.identities.commissioner
    );
    assert_ne!(
        software.identities.owner_key().verifying_key().to_bytes(),
        analytics.identities.owner_key().verifying_key().to_bytes(),
        "the two institutions must not reuse owner signing material"
    );
    let software_config = software.write_host_trust();
    let analytics_config = analytics.write_host_trust();

    require_success(
        run(
            &database_url,
            &[
                Path::new("initialize"),
                &software.prefix(),
                &software_config,
            ],
        )?,
        "software-development installation",
    )?;
    require_success(
        run(
            &database_url,
            &[
                Path::new("initialize"),
                &analytics.prefix(),
                &analytics_config,
            ],
        )?,
        "analytics installation",
    )?;
    software.stage_generation_artifacts();
    analytics.stage_generation_artifacts();
    assert!(
        software
            .prefix()
            .join("workspace/generation/components/executable")
            .is_file()
    );
    assert!(
        analytics
            .prefix()
            .join("workspace/generation/components/migrations.tar")
            .is_file()
    );

    let software_daemon = serve(&database_url, &software)?;
    let analytics_daemon = serve(&database_url, &analytics)?;
    let _ = await_status(&database_url, &software)?;
    let _ = await_status(&database_url, &analytics)?;
    let (software_delegation, software_capture_documents) = software.bootstrap_capture_documents();
    let (analytics_delegation, analytics_capture_documents) =
        analytics.bootstrap_capture_documents();
    let software_delegation_request = write_request(
        &software,
        "software-bootstrap-delegation.json",
        &serde_json::json!({
            "kind": "admit_delegation",
            "delegation": software.signed_commissioner_delegation(software_delegation.clone()),
        }),
    )?;
    let analytics_delegation_request = write_request(
        &analytics,
        "analytics-bootstrap-delegation.json",
        &serde_json::json!({
            "kind": "admit_delegation",
            "delegation": analytics.signed_commissioner_delegation(analytics_delegation.clone()),
        }),
    )?;
    let software_socket = software.prefix().join("run/politeiad.sock");
    let analytics_socket = analytics.prefix().join("run/politeiad.sock");
    let software_admission = require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &software_delegation_request,
            ],
        )?,
        "software direct bootstrap delegation admission",
    )?;
    let analytics_admission = require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &analytics_socket,
                &analytics_delegation_request,
            ],
        )?,
        "analytics direct bootstrap delegation admission",
    )?;
    assert_eq!(
        software_admission["admitted"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        analytics_admission["admitted"],
        serde_json::Value::Bool(true)
    );
    assert_ne!(
        software_admission["delegation"],
        analytics_admission["delegation"]
    );
    fs::copy(
        &software.source_document,
        software.prefix().join("workspace/institution.md"),
    )?;
    fs::copy(
        &analytics.source_document,
        analytics.prefix().join("workspace/institution.md"),
    )?;
    let software_capture = write_request(
        &software,
        "software-capture.json",
        &software_capture_documents.document,
    )?;
    let analytics_capture = write_request(
        &analytics,
        "analytics-capture.json",
        &analytics_capture_documents.document,
    )?;
    let software_capture_result = require_source_capture(
        run(
            &database_url,
            &[Path::new("snapshot"), &software_socket, &software_capture],
        )?,
        "software bootstrap source capture",
    )?;
    let analytics_capture_result = require_source_capture(
        run(
            &database_url,
            &[Path::new("snapshot"), &analytics_socket, &analytics_capture],
        )?,
        "analytics bootstrap source capture",
    )?;
    assert_ne!(
        software_capture_result["snapshot_manifest"],
        analytics_capture_result["snapshot_manifest"]
    );
    let software_candidate =
        software.candidate_documents(&software_delegation, &software_capture_documents);
    let analytics_candidate =
        analytics.candidate_documents(&analytics_delegation, &analytics_capture_documents);
    assert!(software_capture.is_file());
    assert!(analytics_capture.is_file());
    assert_ne!(
        software_candidate.candidate.payload.id,
        analytics_candidate.candidate.payload.id
    );
    assert_ne!(
        software_candidate.approval.payload.candidate_digest,
        analytics_candidate.approval.payload.candidate_digest
    );
    let software_learning =
        software.learning_source_documents(&software_capture_documents, &software_candidate);
    let analytics_learning =
        analytics.learning_source_documents(&analytics_capture_documents, &analytics_candidate);
    let software_approval = write_request(
        &software,
        "software-candidate-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": software_candidate.candidate,
            "approval": software_candidate.approval,
        }),
    )?;
    let analytics_approval = write_request(
        &analytics,
        "analytics-candidate-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": analytics_candidate.candidate,
            "approval": analytics_candidate.approval,
        }),
    )?;
    assert_eq!(
        require_coordinated(
            run(
                &database_url,
                &[
                    Path::new("commissioning"),
                    &software_socket,
                    &software_approval
                ],
            )?,
            "software owner candidate approval",
        )?["approved"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        require_coordinated(
            run(
                &database_url,
                &[
                    Path::new("commissioning"),
                    &analytics_socket,
                    &analytics_approval
                ],
            )?,
            "analytics owner candidate approval",
        )?["approved"],
        serde_json::Value::Bool(true)
    );
    let software_learning_request = write_request(
        &software,
        "software-learning-source.json",
        &software_learning.document,
    )?;
    let analytics_learning_request = write_request(
        &analytics,
        "analytics-learning-source.json",
        &analytics_learning.document,
    )?;
    require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &software_learning_request,
            ],
        )?,
        "software owner learning source registration",
    )?;
    require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &analytics_socket,
                &analytics_learning_request,
            ],
        )?,
        "analytics owner learning source registration",
    )?;
    assert_ne!(software_learning.source, analytics_learning.source);
    let software_status = await_status(&database_url, &software)?;
    let analytics_status = await_status(&database_url, &analytics)?;
    stop(software_daemon)?;
    stop(analytics_daemon)?;

    let LocalOutcome::Ok {
        result:
            politeiad::OperationResult::Coordinated {
                result: software_result,
                ..
            },
    } = software_status.outcome
    else {
        return Err("software daemon refused status after initialization".into());
    };
    let LocalOutcome::Ok {
        result:
            politeiad::OperationResult::Coordinated {
                result: analytics_result,
                ..
            },
    } = analytics_status.outcome
    else {
        return Err("analytics daemon refused status after initialization".into());
    };
    assert_ne!(
        software_result["institution"], analytics_result["institution"],
        "two fixture hosts must have disjoint institutions"
    );
    assert_ne!(
        software_result["workspace"], analytics_result["workspace"],
        "two fixture hosts must have disjoint workspaces"
    );
    assert_eq!(
        software_result["active_generation"],
        serde_json::Value::Null
    );
    assert_eq!(
        analytics_result["active_generation"],
        serde_json::Value::Null
    );
    Ok(())
}
