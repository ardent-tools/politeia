//! Retained observations from the public executable package witness.
//!
//! The transcript records actual process responses, signed inputs, and exact
//! executable identities. It does not turn the harness's assertions into an
//! independent attestation or export institution signing keys.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Mutex,
};

use politeia_core::Digest;
use serde_json::{Value, json};
use tokio_postgres::NoTls;

use super::{ReferenceFixture, TestResult};

static TRANSCRIPT: Mutex<Option<File>> = Mutex::new(None);

/// Durable dispatcher-side state visible after one process request. Each
/// attempt owns one non-null reservation; completion and outbox prove its
/// atomic externalization counterpart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct EffectObservation {
    pub(super) attempts: i64,
    pub(super) completions: i64,
    pub(super) outbox: i64,
}

/// Read only the durable effect boundary. Refusal witnesses compare this
/// before and after a request so a transport failure cannot be mistaken for
/// proof that no attempt/reservation, completion, or outbox record was
/// created.
pub(super) fn observe_effects(
    database_url: &str,
    fixture: &ReferenceFixture,
) -> TestResult<EffectObservation> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (client, connection) = runtime.block_on(tokio_postgres::connect(database_url, NoTls))?;
    let _connection = runtime.spawn(connection);
    let institution = fixture.host_trust.workspace.institution.0;
    let workspace = fixture.host_trust.workspace.id.0;
    let attempts = runtime.block_on(client.query_one(
        "SELECT COUNT(*)::BIGINT,
                COUNT(*) FILTER (WHERE status = 'completed')::BIGINT
         FROM operation_attempts
         WHERE institution_id = $1 AND workspace_id = $2",
        &[&institution, &workspace],
    ))?;
    let outbox = runtime.block_on(client.query_one(
        "SELECT COUNT(*)::BIGINT
         FROM transactional_outbox
         WHERE institution_id = $1 AND workspace_id = $2",
        &[&institution, &workspace],
    ))?;
    Ok(EffectObservation {
        attempts: attempts.get(0),
        completions: attempts.get(1),
        outbox: outbox.get(0),
    })
}

/// Check whether one named governed-state artifact was durably written. This
/// is used for capture refusal probes whose semantic artifact is a state entry
/// rather than an operation-completion response.
pub(super) fn state_entry_exists(
    database_url: &str,
    fixture: &ReferenceFixture,
    key: &str,
) -> TestResult<bool> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (client, connection) = runtime.block_on(tokio_postgres::connect(database_url, NoTls))?;
    let _connection = runtime.spawn(connection);
    let institution = fixture.host_trust.workspace.institution.0;
    let workspace = fixture.host_trust.workspace.id.0;
    let exists = runtime.block_on(client.query_opt(
        "SELECT 1 FROM state_entries
         WHERE institution_id = $1 AND workspace_id = $2 AND state_key = $3",
        &[&institution, &workspace, &key],
    ))?;
    Ok(exists.is_some())
}

pub(super) struct Session {
    path: Option<PathBuf>,
    finished: bool,
}

impl Session {
    pub(super) fn begin(client: &str, daemon: &str) -> TestResult<Self> {
        let Some(directory) = std::env::var_os("POLITEIA_ACCEPTANCE_ARTIFACT_DIR") else {
            return Ok(Self {
                path: None,
                finished: false,
            });
        };
        fs::create_dir_all(&directory)?;
        let path = PathBuf::from(directory).join(format!("package-{}.jsonl", uuid::Uuid::now_v7()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        *TRANSCRIPT.lock().expect("transcript lock is not poisoned") = Some(file);
        let session = Self {
            path: Some(path),
            finished: false,
        };
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let revision = Command::new("git")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .current_dir(&repository)
            .args(["rev-parse", "HEAD"])
            .output()?;
        if !revision.status.success() {
            return Err("the acceptance transcript requires the source checkout revision".into());
        }
        let changes = Command::new("git")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .current_dir(&repository)
            .args(["diff", "--binary", "HEAD"])
            .output()?;
        if !changes.status.success() {
            return Err("the acceptance transcript could not identify source changes".into());
        }
        record_observation(
            "harness",
            &json!({
                "schema": "politeia.executable-package-observations.v1",
                "source_revision": String::from_utf8(revision.stdout)?.trim(),
                "source_changes_digest": Digest::blake3(&changes.stdout),
                "source_has_tracked_changes": !changes.stdout.is_empty(),
                "client_executable_digest": Digest::blake3(&fs::read(client)?),
                "daemon_executable_digest": Digest::blake3(&fs::read(daemon)?),
                "test_executable_digest": Digest::blake3(&fs::read(std::env::current_exe()?)?),
                "started_at": jiff::Timestamp::now(),
            }),
        )?;
        Ok(session)
    }

    pub(super) fn finish(mut self, summary: &Value) -> TestResult {
        record_observation("completed_package", summary)?;
        if let Some(file) = TRANSCRIPT
            .lock()
            .expect("transcript lock is not poisoned")
            .take()
        {
            file.sync_all()?;
        }
        self.finished = true;
        if let Some(path) = &self.path {
            eprintln!("retained package observations: {}", path.display());
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.finished && self.path.is_some() {
            let _ = record_observation("incomplete_package", &json!({"completed": false}));
            TRANSCRIPT
                .lock()
                .expect("transcript lock is not poisoned")
                .take();
        }
    }
}

pub(super) fn record_observation(label: &str, observation: &Value) -> TestResult {
    if let Some(file) = TRANSCRIPT
        .lock()
        .expect("transcript lock is not poisoned")
        .as_mut()
    {
        serde_json::to_writer(
            &mut *file,
            &json!({"kind": label, "observation": observation}),
        )?;
        file.write_all(b"\n")?;
        file.flush()?;
    }
    Ok(())
}

pub(super) fn record_process(arguments: &[&Path], output: &Output) -> TestResult {
    let request = arguments
        .last()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            fs::read(path).and_then(|bytes| {
                serde_json::from_slice::<Value>(&bytes).map_err(std::io::Error::other)
            })
        })
        .transpose()?;
    record_observation(
        "process_response",
        &json!({
            "command": arguments.first().map(|path| path.to_string_lossy()),
            "request_document": arguments.last().and_then(|path| path.file_name()).map(|name| name.to_string_lossy()),
            "request": request,
            "exit_code": output.status.code(),
            "success": output.status.success(),
            "stdout": serde_json::from_slice::<Value>(&output.stdout).ok(),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    )
}
