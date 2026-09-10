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

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_politeiad")
}

fn command(database_url: &str, arguments: &[&Path]) -> Command {
    let mut command = Command::new(binary());
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

fn serve(database_url: &str, fixture: &ReferenceFixture) -> TestResult<Daemon> {
    Ok(Daemon(
        command(database_url, &[Path::new("serve"), &fixture.prefix()]).spawn()?,
    ))
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
    let software = ReferenceFixture::new(ReferenceInstitutionKind::SoftwareDevelopment);
    let analytics = ReferenceFixture::new(ReferenceInstitutionKind::Analytics);
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

    let software_daemon = serve(&database_url, &software)?;
    let analytics_daemon = serve(&database_url, &analytics)?;
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
