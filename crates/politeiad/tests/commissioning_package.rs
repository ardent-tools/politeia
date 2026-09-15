//! Executable substrate acceptance for two disjoint synthetic institutions.
//!
//! The test starts the compiled administrative CLI and daemon against the same
//! disposable PostgreSQL service used by the durable-storage acceptance tests.
//! Protected work crosses the CLI and Unix socket. Test-only PostgreSQL
//! administration observes durable records and pauses completion to force an
//! exact interruption; it never admits product state or invokes an effect.

#![expect(
    clippy::expect_used,
    reason = "acceptance fixtures must fail loudly when a process or response violates its contract"
)]

#[path = "package_support/mod.rs"]
mod package_support;

#[path = "package_process/continuity.rs"]
mod continuity;
#[path = "package_process/evidence.rs"]
mod evidence;
#[path = "package_process/executable_identity.rs"]
mod executable_identity;
#[path = "package_process/handoff.rs"]
mod handoff;
#[path = "package_process/learning.rs"]
mod learning;
#[path = "package_process/lifecycle.rs"]
mod lifecycle;

use std::{
    error::Error,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use package_support::operational::OperationalFixture;
use package_support::{ReferenceFixture, ReferenceInstitutionKind};
use politeia_core::{Delegation, Digest};
use politeiad::service_generation::CommissioningReceipt;
use politeiad::transport::{LocalOutcome, LocalResponse};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

struct CommissionedGeneration {
    generation: Digest,
    owner_root: Delegation,
    commissioner: Delegation,
    receipt: CommissioningReceipt,
    publication: serde_json::Value,
}

fn status_value(database_url: &str, fixture: &ReferenceFixture) -> TestResult<serde_json::Value> {
    let response = await_status(database_url, fixture)?;
    match response.outcome {
        LocalOutcome::Ok {
            result: politeiad::OperationResult::Coordinated { result, .. },
        } => Ok(result),
        outcome => Err(format!("status did not return a durable snapshot: {outcome:?}").into()),
    }
}

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
    RunningChild::spawn(database_url, arguments, Instant::now() + REQUEST_TIMEOUT)?
        .wait_with_output()
}

type OutputReader = thread::JoinHandle<io::Result<Vec<u8>>>;

/// Own the CLI and drain both pipes while enforcing its request deadline.
/// Early fixture failure kills and reaps the child before joining its readers.
struct RunningChild {
    child: Child,
    arguments: Vec<PathBuf>,
    deadline: Instant,
    request_id: uuid::Uuid,
    stdout: Option<OutputReader>,
    stderr: Option<OutputReader>,
}

impl RunningChild {
    fn spawn(database_url: &str, arguments: &[&Path], deadline: Instant) -> TestResult<Self> {
        let mut command = command(database_url, arguments);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process = Self {
            child: command.spawn()?,
            arguments: arguments.iter().map(|path| path.to_path_buf()).collect(),
            deadline,
            request_id: uuid::Uuid::now_v7(),
            stdout: None,
            stderr: None,
        };
        process.stdout = Some(read_output(
            process
                .child
                .stdout
                .take()
                .ok_or("CLI stdout was not piped")?,
        )?);
        process.stderr = Some(read_output(
            process
                .child
                .stderr
                .take()
                .ok_or("CLI stderr was not piped")?,
        )?);
        evidence::record_process_started(arguments, process.request_id, process.child.id())?;
        Ok(process)
    }

    fn wait_with_output(mut self) -> TestResult<Output> {
        let arguments: Vec<_> = self.arguments.iter().map(PathBuf::as_path).collect();
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= self.deadline {
                evidence::record_observation(
                    "process_deadline_exceeded",
                    &serde_json::json!({
                        "request_id": self.request_id,
                        "process_id": self.child.id(),
                    }),
                )?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("CLI request {arguments:?} exceeded its process deadline"),
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let output = Output {
            status,
            stdout: join_output(self.stdout.take())?,
            stderr: join_output(self.stderr.take())?,
        };
        evidence::record_process(&arguments, self.request_id, &output)?;
        Ok(output)
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in [self.stdout.take(), self.stderr.take()]
            .into_iter()
            .flatten()
        {
            let _ = reader.join();
        }
    }
}

fn read_output(mut pipe: impl Read + Send + 'static) -> io::Result<OutputReader> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_output(reader: Option<OutputReader>) -> TestResult<Vec<u8>> {
    Ok(reader
        .ok_or("CLI output reader was already consumed")?
        .join()
        .map_err(|_| "CLI output reader panicked")??)
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

fn require_refusal(output: &Output, phase: &str, expected: &str) -> TestResult {
    if output.status.success() {
        return Err(format!("{phase} unexpectedly succeeded").into());
    }
    let detail = format!(
        "{}\n{}",
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );
    if detail.contains(expected) {
        return Ok(());
    }
    Err(format!("{phase} did not report `{expected}`: {detail}").into())
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
        let output = RunningChild::spawn(database_url, &[Path::new("status"), &socket], deadline)?
            .wait_with_output()?;
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

#[test]
fn unanswered_cli_request_reaches_its_deadline_and_closes() -> TestResult {
    let fixture = ReferenceFixture::new(
        ReferenceInstitutionKind::SoftwareDevelopment,
        Path::new(daemon_binary()),
    );
    let socket = fixture.root.join("unanswered.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = RunningChild::spawn("", &[Path::new("status"), &socket], deadline)?;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("fixture CLI did not connect to the unanswered socket".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut reader = io::BufReader::new(stream);
    let mut request = String::new();
    io::BufRead::read_line(&mut reader, &mut request)?;
    let _: politeiad::transport::LocalRequest = serde_json::from_str(&request)?;
    assert!(process.child.try_wait()?.is_none());
    process.deadline = Instant::now();
    let error = process
        .wait_with_output()
        .expect_err("a connected client with no response must exceed its deadline");
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(reader.read_to_end(&mut Vec::new())?, 0);
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
    let evidence = evidence::Session::begin(client_binary(), daemon_binary())?;
    let database_url = database_url()?;
    assert_ne!(client_binary(), daemon_binary());
    evidence::record_observation(
        "mismatched_daemon_executable",
        &executable_identity::exercise(&database_url)?,
    )?;
    let executable = Path::new(daemon_binary());
    let mut software =
        ReferenceFixture::new(ReferenceInstitutionKind::SoftwareDevelopment, executable);
    let mut analytics = ReferenceFixture::new(ReferenceInstitutionKind::Analytics, executable);
    let software_operations = OperationalFixture::install(&mut software);
    let analytics_operations = OperationalFixture::install(&mut analytics);
    evidence::record_observation(
        "installed_trust",
        &serde_json::json!({
            "software_development": software.host_trust,
            "analytics": analytics.host_trust,
        }),
    )?;
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
    let software_capture_documents = software.capture_after_admission(&software_capture_documents);
    let analytics_capture_documents =
        analytics.capture_after_admission(&analytics_capture_documents);
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
    let forged_software_approval = write_request(
        &software,
        "software-forged-candidate-approval.json",
        &software.forged_candidate_approval(&software_candidate),
    )?;
    require_refusal(
        &run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &forged_software_approval,
            ],
        )?,
        "forged software owner approval",
        "Ed25519 signature does not verify",
    )?;
    let cross_institution_approval = write_request(
        &analytics,
        "foreign-candidate-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": software_candidate.candidate.clone(),
            "approval": software_candidate.approval.clone(),
        }),
    )?;
    require_refusal(
        &run(
            &database_url,
            &[
                Path::new("commissioning"),
                &analytics_socket,
                &cross_institution_approval,
            ],
        )?,
        "foreign institution candidate approval",
        "statement names another institution",
    )?;
    let software_learning =
        software.learning_source_documents(&software_capture_documents, &software_candidate);
    let analytics_learning =
        analytics.learning_source_documents(&analytics_capture_documents, &analytics_candidate);
    let software_approval = write_request(
        &software,
        "software-candidate-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": software_candidate.candidate.clone(),
            "approval": software_candidate.approval.clone(),
        }),
    )?;
    let analytics_approval = write_request(
        &analytics,
        "analytics-candidate-approval.json",
        &serde_json::json!({
            "kind": "approve_claim",
            "candidate": analytics_candidate.candidate.clone(),
            "approval": analytics_candidate.approval.clone(),
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
    let (software_context_delegation, software_context) =
        software.bootstrap_context_documents(&software_learning.source);
    let software_context_delegation_request = write_request(
        &software,
        "software-context-delegation.json",
        &serde_json::json!({
            "kind": "admit_delegation",
            "delegation": software.signed_commissioner_delegation(software_context_delegation.clone()),
        }),
    )?;
    require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &software_context_delegation_request,
            ],
        )?,
        "software context delegation admission",
    )?;
    let forged_context_request = write_request(
        &software,
        "software-forged-context-requester.json",
        &software.forged_context_requester(&software_context_delegation),
    )?;
    require_refusal(
        &run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &forged_context_request,
            ],
        )?,
        "software forged context requester",
        "learning requester differs from the verified disclosure envelope signer",
    )?;
    let software_context_request = write_request(
        &software,
        "software-bootstrap-context.json",
        &software_context,
    )?;
    let context = require_coordinated(
        run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &software_context_request,
            ],
        )?,
        "software bootstrap context disclosure",
    )?;
    assert_eq!(
        context["context"]["input_ids"][0],
        serde_json::json!(software_learning.source)
    );
    assert_eq!(
        context["content"][software_learning.source.0.to_string()],
        serde_json::json!(fs::read(&software.source_document)?)
    );
    require_refusal(
        &run(
            &database_url,
            &[
                Path::new("commissioning"),
                &software_socket,
                &software_context_request,
            ],
        )?,
        "software bootstrap context replay",
        "replay",
    )?;
    let software_generation =
        commission_generation(&database_url, &software, &software_capture_documents)?;
    let analytics_generation =
        commission_generation(&database_url, &analytics, &analytics_capture_documents)?;
    assert_ne!(
        software_generation.generation, analytics_generation.generation,
        "institutional inputs derive disjoint generations"
    );
    for (fixture, operations, generation) in [
        (&software, &software_operations, &software_generation),
        (&analytics, &analytics_operations, &analytics_generation),
    ] {
        for (index, document) in operations.admission_requests().iter().enumerate() {
            submit_commissioning(
                &database_url,
                fixture,
                &format!("operational-evidence-{index}.json"),
                document,
            )?;
        }
        lifecycle::activate(
            &database_url,
            fixture,
            operations,
            &generation.generation,
            "activate",
            true,
        )?;
    }

    let mut software_temporary_grants = vec![software_delegation, software_context_delegation];
    let software_learned = learning::exercise(
        &database_url,
        &software,
        &software_operations,
        &software_generation.generation,
        &software_learning,
        &software_candidate,
        &software_capture_documents,
    )?;
    let mut analytics_temporary_grants = vec![analytics_delegation];
    let analytics_learned = learning::exercise(
        &database_url,
        &analytics,
        &analytics_operations,
        &analytics_generation.generation,
        &analytics_learning,
        &analytics_candidate,
        &analytics_capture_documents,
    )?;

    // Kill the actual daemon processes after learning has committed. New
    // processes must recover their active generation and durable replay state.
    stop(software_daemon)?;
    stop(analytics_daemon)?;
    let software_daemon = serve(&database_url, &software)?;
    let analytics_daemon = serve(&database_url, &analytics)?;
    for (fixture, generation, learned) in [
        (
            &software,
            &software_generation.generation,
            &software_learned,
        ),
        (
            &analytics,
            &analytics_generation.generation,
            &analytics_learned,
        ),
    ] {
        assert_eq!(
            status_value(&database_url, fixture)?["active_generation"],
            serde_json::json!(generation)
        );
        require_refusal(
            &run(
                &database_url,
                &[
                    Path::new("commissioning"),
                    &fixture.prefix().join("run/politeiad.sock"),
                    &fixture.root.join("corrected-active-context.json"),
                ],
            )?,
            "committed active context replay after process restart",
            "replay",
        )?;
        let after_restart =
            continuity::observe_completed_disclosure(&database_url, fixture, &learned.completion)?;
        assert_eq!(
            after_restart, learned.durable_completion,
            "completed disclosure evidence survives an actual daemon restart unchanged"
        );
        evidence::record_observation("disclosure_after_restart", &after_restart)?;
        let historical_context = continuity::observe_completed_disclosure(
            &database_url,
            fixture,
            &learned.historical_context,
        )?;
        assert_eq!(
            historical_context, learned.historical_context_receipt,
            "the original delivered context survives correction and restart unchanged"
        );
        evidence::record_observation("historical_context_after_restart", &historical_context)?;
        let approval_key = learned.historical_approval["key"]
            .as_str()
            .ok_or("historical approval observation omitted its state key")?;
        let historical_approval =
            continuity::observe_signed_state(&database_url, fixture, approval_key)?;
        assert_eq!(
            historical_approval, learned.historical_approval,
            "the original signed approval survives correction and restart unchanged"
        );
        evidence::record_observation("historical_approval_after_restart", &historical_approval)?;
    }
    software_temporary_grants.extend(software_learned.temporary_grants);
    analytics_temporary_grants.extend(analytics_learned.temporary_grants);
    let software_continuity = continuity::exercise(
        &database_url,
        &software,
        &software_operations,
        software_daemon,
    )?;
    evidence::record_observation(
        "software_effect_continuity",
        &software_continuity.observations,
    )?;
    let software_daemon = software_continuity.daemon;
    let analytics_continuity = continuity::exercise(
        &database_url,
        &analytics,
        &analytics_operations,
        analytics_daemon,
    )?;
    evidence::record_observation(
        "analytics_effect_continuity",
        &analytics_continuity.observations,
    )?;
    let analytics_daemon = analytics_continuity.daemon;
    let software_replacement = handoff::exercise(
        &database_url,
        &software,
        &software_operations,
        &software_generation,
        &software_temporary_grants,
    )?;
    let analytics_replacement = handoff::exercise(
        &database_url,
        &analytics,
        &analytics_operations,
        &analytics_generation,
        &analytics_temporary_grants,
    )?;
    assert_ne!(software_replacement, analytics_replacement);
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
        serde_json::json!(software_generation.generation)
    );
    assert_eq!(
        analytics_result["active_generation"],
        serde_json::json!(analytics_generation.generation)
    );
    evidence.finish(&serde_json::json!({
        "software_development": software_result,
        "analytics": analytics_result,
        "software_replacement_generation": software_replacement,
        "analytics_replacement_generation": analytics_replacement,
    }))
}

fn submit_commissioning(
    database_url: &str,
    fixture: &ReferenceFixture,
    name: &str,
    document: &serde_json::Value,
) -> TestResult<serde_json::Value> {
    let path = write_request(fixture, name, document)?;
    require_coordinated(
        run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &path,
            ],
        )?,
        name,
    )
}

fn commission_generation(
    database_url: &str,
    fixture: &ReferenceFixture,
    capture: &package_support::CaptureDocuments,
) -> TestResult<CommissionedGeneration> {
    use politeia_core::commissioning::CommissionerGrantRecord;

    let root = fixture.owner_root_delegation();
    submit_commissioning(
        database_url,
        fixture,
        "owner-root.json",
        &serde_json::json!({
            "kind": "admit_delegation", "delegation": fixture.signed_commissioner_delegation(root.clone()),
        }),
    )?;
    let commissioner = fixture.commissioner_delegation(&root);
    let admitted = submit_commissioning(
        database_url,
        fixture,
        "commissioner.json",
        &serde_json::json!({
            "kind": "admit_delegation", "delegation": fixture.signed_commissioner_delegation(commissioner.clone()),
        }),
    )?;
    let admitted_at: jiff::Timestamp = serde_json::from_value(admitted["admitted_at"].clone())?;
    let grant_digest: Digest =
        serde_json::from_value(admitted["commissioner_grant_digest"].clone())?;
    assert_eq!(
        grant_digest,
        CommissionerGrantRecord {
            institution: fixture.host_trust.workspace.institution.clone(),
            workspace: fixture.host_trust.workspace.id.clone(),
            valid_from: admitted_at,
            revoked_at: None,
            delegation: commissioner.clone(),
        }
        .digest()?,
        "public admission receipt identifies the exact durable grant"
    );
    let approvals = fixture.commissioning_approvals(capture);
    let approval_ids: Vec<_> = approvals
        .iter()
        .map(|wire| wire.payload.id.clone())
        .collect();
    for (index, evidence) in approvals.into_iter().enumerate() {
        submit_commissioning(
            database_url,
            fixture,
            &format!("owner-approval-{index}.json"),
            &serde_json::json!({
                "kind": "commissioning_approval", "evidence": evidence,
            }),
        )?;
    }
    let selection = serde_json::json!({
        "delegation": commissioner.id, "observations": [capture.evidence],
        "approvals": approval_ids, "unresolved_obligations": [],
    });
    let mut empty_selection = selection.clone();
    empty_selection["observations"] = serde_json::json!([]);
    let path = write_request(
        fixture,
        "empty-observation-receipt.json",
        &serde_json::json!({
            "kind": "generation", "request": { "kind": "derive_record", "selection": empty_selection },
        }),
    )?;
    require_refusal(
        &run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &path,
            ],
        )?,
        "empty observation commissioning receipt",
        "commissioning has no observations",
    )?;
    let receipt: CommissioningReceipt = serde_json::from_value(submit_commissioning(
        database_url,
        fixture,
        "derive-record.json",
        &serde_json::json!({
            "kind": "generation", "request": { "kind": "derive_record", "selection": selection },
        }),
    )?)?;
    assert_eq!(receipt.commissioner_grant_digest, grant_digest);
    assert_eq!(receipt.delegation, commissioner.id);
    assert!(receipt.captured_at >= admitted_at);
    assert_eq!(
        receipt.observations,
        std::collections::BTreeSet::from([capture.evidence.clone()])
    );
    let documents = fixture.generation_documents(&commissioner, &receipt);
    assert_eq!(
        documents.inputs.payload.commissioning_record_digest,
        receipt.record_digest
    );
    let published = submit_commissioning(
        database_url,
        fixture,
        "publish-generation.json",
        &documents.publish,
    )?;
    let generation: Digest = serde_json::from_value(published["generation"].clone())?;
    assert_eq!(published["admitted"], true);
    let verified = submit_commissioning(
        database_url,
        fixture,
        "verify-generation.json",
        &serde_json::json!({
            "kind": "generation", "request": { "kind": "verify", "generation": generation },
        }),
    )?;
    assert_eq!(verified["verified"], true);
    assert_eq!(
        verified["artifact_manifest"],
        published["artifact_manifest"]
    );
    let reproduced = submit_commissioning(
        database_url,
        fixture,
        "reproduce-generation.json",
        &serde_json::json!({
            "kind": "generation", "request": { "kind": "reproduce", "generation": generation },
        }),
    )?;
    assert_eq!(reproduced["generation_reproduced"], true);
    assert_eq!(
        reproduced["artifact_manifest"],
        published["artifact_manifest"]
    );
    Ok(CommissionedGeneration {
        generation,
        owner_root: root,
        commissioner,
        receipt,
        publication: documents.publish,
    })
}
