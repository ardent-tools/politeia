//! Process interruption and overlap witnesses for protected operations.
//!
//! The barrier below is test-only PostgreSQL administration. It never constructs
//! a Politeia service, coordinator, or storage object: real CLI calls reserve,
//! claim, and attempt completion through the daemon. The barrier merely holds
//! the final database transaction after a durable claim, so the test can kill
//! the actual daemon at a deterministic boundary.

use std::{
    collections::BTreeSet,
    path::Path,
    process::Child,
    thread,
    time::{Duration, Instant},
};

use jiff::Timestamp;
use politeia_core::Digest;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

use super::{
    Daemon, OperationalFixture, ReferenceFixture, TestResult, await_status, command,
    require_coordinated, require_refusal, run, serve, stop, submit_commissioning, write_request,
};

const REPLAY_REFUSAL: &str = "attempt is missing, expired, replayed, or not claimable";
const BARRIER_TABLE: &str = "politeia_test_completion_barriers";
const BARRIER_TRIGGER: &str = "politeia_test_block_operation_completion";
const BARRIER_FUNCTION: &str = "politeia_test_block_completion";

/// Interrupt a real daemon after claim and prove durable replay conservatism.
///
/// The returned daemon is a fresh process on the same installation, ready for
/// the caller's remaining lifecycle and handoff checks.
pub(super) fn exercise(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    daemon: Daemon,
) -> TestResult<ContinuityExercise> {
    let crashed = operations.positive_manifest(fixture, Timestamp::now());
    submit_commissioning(
        database_url,
        fixture,
        "continuity-crash-authority.json",
        &crashed.authority_admission,
    )?;
    let crashed_request =
        write_request(fixture, "continuity-crash-operate.json", &crashed.operate)?;

    let mut barrier = CompletionBarrier::install(database_url, fixture)?;
    let crashed_operation = spawn_operate(database_url, fixture, &crashed_request)?;
    let reservation = barrier.wait_for_claim_and_block()?;
    let crash_barrier = barrier.observation(&reservation)?;
    stop(daemon)?;
    let crashed_output = crashed_operation.wait()?;
    assert!(
        !crashed_output.status.success(),
        "the killed daemon cannot report a completion from its blocked transaction"
    );
    let crashed_attempt = barrier.assert_claimed_without_completion(&reservation)?;
    barrier.release()?;
    barrier.cleanup()?;

    let daemon = serve(database_url, fixture)?;
    let _ = await_status(database_url, fixture)?;
    require_refusal(
        run(
            database_url,
            &[
                Path::new("operate"),
                &fixture.prefix().join("run/politeiad.sock"),
                &crashed_request,
            ],
        )?,
        "post-crash replay of the claimed operation",
        REPLAY_REFUSAL,
    )?;

    let overlap_observation = concurrent_one_winner(database_url, fixture, operations)?;
    Ok(ContinuityExercise {
        daemon,
        observations: serde_json::json!({
            "crash_after_claim": {
                "barrier": crash_barrier,
                "durable_attempt": crashed_attempt,
            },
            "concurrent_overlap": overlap_observation,
        }),
    })
}

/// A fresh daemon and the exact durable boundaries observed during the exercise.
pub(super) struct ContinuityExercise {
    pub(super) daemon: Daemon,
    pub(super) observations: serde_json::Value,
}

fn concurrent_one_winner(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
) -> TestResult<serde_json::Value> {
    let prepared = operations.positive_manifest(fixture, Timestamp::now());
    submit_commissioning(
        database_url,
        fixture,
        "continuity-overlap-authority.json",
        &prepared.authority_admission,
    )?;
    let request = write_request(
        fixture,
        "continuity-overlap-operate.json",
        &prepared.operate,
    )?;

    let mut barrier = CompletionBarrier::install(database_url, fixture)?;
    let winner = spawn_operate(database_url, fixture, &request)?;
    let reservation = barrier.wait_for_claim_and_block()?;
    let observation = barrier.observation(&reservation)?;
    let loser = spawn_operate(database_url, fixture, &request)?;
    require_refusal(
        loser.wait()?,
        "overlapping identical operation request",
        REPLAY_REFUSAL,
    )?;

    barrier.release()?;
    let completed = require_coordinated(
        winner.wait()?,
        "winner of overlapping identical operation request",
    )?;
    assert_completion_ids(&completed)?;
    let completion_observation = barrier.assert_completed(&reservation, &completed)?;
    barrier.cleanup()?;
    Ok(serde_json::json!({
        "barrier": observation,
        "completion": completion_observation,
    }))
}

fn spawn_operate(
    database_url: &str,
    fixture: &ReferenceFixture,
    request: &Path,
) -> TestResult<Child> {
    Ok(command(
        database_url,
        &[
            Path::new("operate"),
            &fixture.prefix().join("run/politeiad.sock"),
            request,
        ],
    )
    .spawn()?)
}

fn assert_completion_ids(completion: &serde_json::Value) -> TestResult {
    for field in ["receipt", "reservation", "outbox"] {
        let value = completion[field]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("the concurrent winner omitted its {field} identity"))?;
        let parsed = Uuid::parse_str(value)?;
        assert_eq!(
            parsed.hyphenated().to_string(),
            value,
            "the concurrent winner returned a canonical lowercase-hyphenated {field} UUID"
        );
    }
    let _: Digest = serde_json::from_value(completion["receipt_digest"].clone())?;
    Ok(())
}

/// One test-side connection that holds the advisory lock used by the trigger.
struct CompletionBarrier {
    runtime: tokio::runtime::Runtime,
    client: Client,
    _connection: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
    institution: Uuid,
    workspace: Uuid,
    lock_key: i64,
    prior_claims: BTreeSet<Uuid>,
    blocked_backend: Option<i32>,
    released: bool,
}

impl CompletionBarrier {
    fn install(database_url: &str, fixture: &ReferenceFixture) -> TestResult<Self> {
        let runtime = tokio::runtime::Runtime::new()?;
        let (client, connection) =
            runtime.block_on(tokio_postgres::connect(database_url, NoTls))?;
        let connection = runtime.spawn(connection);
        let institution = fixture.host_trust.workspace.institution.0;
        let workspace = fixture.host_trust.workspace.id.0;
        let lock_key = i64::try_from(
            u64::from_be_bytes(
                Uuid::now_v7().as_bytes()[..8]
                    .try_into()
                    .expect("UUID prefix is eight bytes"),
            ) & (i64::MAX as u64),
        )?;
        let mut barrier = Self {
            runtime,
            client,
            _connection: connection,
            institution,
            workspace,
            lock_key,
            prior_claims: BTreeSet::new(),
            blocked_backend: None,
            released: false,
        };
        barrier.install_schema()?;
        barrier.runtime.block_on(async {
            barrier
                .client
                .execute(
                    "INSERT INTO politeia_test_completion_barriers \
                     (institution_id, workspace_id, advisory_key, reservation_id) \
                     VALUES ($1, $2, $3, NULL) \
                     ON CONFLICT (institution_id, workspace_id) \
                     DO UPDATE SET advisory_key = EXCLUDED.advisory_key, reservation_id = NULL",
                    &[&barrier.institution, &barrier.workspace, &barrier.lock_key],
                )
                .await?;
            barrier
                .client
                .query_one("SELECT pg_advisory_lock($1)", &[&barrier.lock_key])
                .await?;
            Ok::<_, tokio_postgres::Error>(())
        })?;
        barrier.prior_claims = barrier.claimed_without_receipt()?.into_iter().collect();
        Ok(barrier)
    }

    fn install_schema(&self) -> TestResult {
        self.runtime.block_on(self.client.batch_execute(&format!(
            r#"
CREATE TABLE IF NOT EXISTS {BARRIER_TABLE} (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    advisory_key BIGINT NOT NULL,
    reservation_id UUID,
    PRIMARY KEY (institution_id, workspace_id)
);
ALTER TABLE {BARRIER_TABLE} ADD COLUMN IF NOT EXISTS reservation_id UUID;
CREATE OR REPLACE FUNCTION {BARRIER_FUNCTION}() RETURNS trigger AS $$
DECLARE lock_key BIGINT;
BEGIN
    SELECT advisory_key INTO lock_key FROM {BARRIER_TABLE}
      WHERE institution_id = NEW.institution_id
        AND workspace_id = NEW.workspace_id
        AND (reservation_id IS NULL OR reservation_id = NEW.reservation_id);
    IF FOUND AND OLD.status = 'claimed' AND NEW.status = 'completed' THEN
        PERFORM pg_advisory_xact_lock(lock_key);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS {BARRIER_TRIGGER} ON operation_attempts;
CREATE TRIGGER {BARRIER_TRIGGER}
    BEFORE UPDATE OF status ON operation_attempts
    FOR EACH ROW EXECUTE FUNCTION {BARRIER_FUNCTION}();
"#
        )))?;
        Ok(())
    }

    fn wait_for_claim_and_block(&mut self) -> TestResult<Uuid> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let claims: Vec<_> = self
                .claimed_without_receipt()?
                .into_iter()
                .filter(|reservation| !self.prior_claims.contains(reservation))
                .collect();
            if claims.len() > 1 {
                return Err("completion barrier observed more than one claimed operation".into());
            }
            if let Some(reservation) = claims.first()
                && let Some(backend) = self.waiting_backend_at_barrier()?
            {
                self.bind_reservation(reservation)?;
                self.blocked_backend = Some(backend);
                return Ok(*reservation);
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err("operation did not reach the deterministic post-claim completion barrier".into())
    }

    fn claimed_without_receipt(&self) -> TestResult<Vec<Uuid>> {
        Ok(self
            .runtime
            .block_on(self.client.query(
                "SELECT reservation_id FROM operation_attempts
                 WHERE institution_id = $1 AND workspace_id = $2
                   AND status = 'claimed' AND receipt_digest IS NULL
                 ORDER BY created_at",
                &[&self.institution, &self.workspace],
            ))?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn bind_reservation(&self, reservation: &Uuid) -> TestResult {
        let bound = self.runtime.block_on(self.client.execute(
            "UPDATE politeia_test_completion_barriers
             SET reservation_id = $3
             WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id IS NULL",
            &[&self.institution, &self.workspace, reservation],
        ))?;
        if bound != 1 {
            return Err("completion barrier did not bind its observed claimed reservation".into());
        }
        Ok(())
    }

    fn waiting_backend_at_barrier(&self) -> TestResult<Option<i32>> {
        let key = self.lock_key as u64;
        let class_id = (key >> 32) as u32;
        let object_id = key as u32;
        let rows = self.runtime.block_on(self.client.query(
            "SELECT pid FROM pg_locks
                 WHERE locktype = 'advisory'
                   AND classid = $1::oid
                   AND objid = $2::oid
                   AND objsubid = 1
                   AND NOT granted",
            &[&class_id, &object_id],
        ))?;
        if rows.len() > 1 {
            return Err("more than one daemon backend waited at the completion barrier".into());
        }
        Ok(rows.first().map(|row| row.get(0)))
    }

    fn observation(&self, reservation: &Uuid) -> TestResult<serde_json::Value> {
        let backend = self
            .blocked_backend
            .ok_or("completion barrier has no observed blocked backend")?;
        Ok(serde_json::json!({
            "institution": self.institution,
            "workspace": self.workspace,
            "reservation": reservation,
            "advisory_lock_key": self.lock_key,
            "blocked_backend_pid": backend,
        }))
    }

    fn assert_claimed_without_completion(
        &self,
        reservation: &Uuid,
    ) -> TestResult<serde_json::Value> {
        let row = self.runtime.block_on(self.client.query_one(
            "SELECT status::text, receipt_digest IS NULL, receipt_payload IS NULL, completed_at IS NULL
             FROM operation_attempts
             WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3",
            &[&self.institution, &self.workspace, reservation],
        ))?;
        assert_eq!(row.get::<_, String>(0), "claimed");
        assert!(row.get::<_, bool>(1));
        assert!(row.get::<_, bool>(2));
        assert!(row.get::<_, bool>(3));
        Ok(serde_json::json!({
            "reservation": reservation,
            "status": row.get::<_, String>(0),
            "receipt_digest": serde_json::Value::Null,
            "receipt_payload": serde_json::Value::Null,
            "completed_at": serde_json::Value::Null,
        }))
    }

    fn assert_completed(
        &self,
        reservation: &Uuid,
        completion: &serde_json::Value,
    ) -> TestResult<serde_json::Value> {
        let row = self.runtime.block_on(self.client.query_one(
            "SELECT status::text, receipt_digest IS NOT NULL, receipt_payload IS NOT NULL, completed_at IS NOT NULL
             FROM operation_attempts
             WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3",
            &[&self.institution, &self.workspace, reservation],
        ))?;
        assert_eq!(row.get::<_, String>(0), "completed");
        assert!(row.get::<_, bool>(1));
        assert!(row.get::<_, bool>(2));
        assert!(row.get::<_, bool>(3));
        let receipt_digest: String = self
            .runtime
            .block_on(self.client.query_one(
                "SELECT receipt_digest FROM operation_attempts
             WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3",
                &[&self.institution, &self.workspace, reservation],
            ))?
            .get(0);
        let outbox = completion["outbox"]
            .as_str()
            .ok_or("completed operation omitted its outbox identifier")?;
        let outbox = Uuid::parse_str(outbox)?;
        let outbox_persisted: bool = self
            .runtime
            .block_on(self.client.query_one(
                "SELECT EXISTS (
                SELECT FROM transactional_outbox
                 WHERE institution_id = $1 AND workspace_id = $2 AND outbox_id = $3
            )",
                &[&self.institution, &self.workspace, &outbox],
            ))?
            .get(0);
        assert!(
            outbox_persisted,
            "completed operation committed its returned outbox row"
        );
        assert_eq!(
            completion["reservation"],
            serde_json::json!(reservation),
            "completed operation returned the exact reservation observed at the barrier"
        );
        assert_eq!(
            completion["receipt_digest"],
            serde_json::json!(receipt_digest),
            "completed operation returned the durable canonical receipt digest"
        );
        Ok(serde_json::json!({
            "reservation": reservation,
            "receipt": completion["receipt"],
            "receipt_digest": receipt_digest,
            "outbox": outbox,
            "outbox_persisted": outbox_persisted,
        }))
    }

    fn release(&mut self) -> TestResult {
        if !self.released {
            let unlocked: bool = self
                .runtime
                .block_on(
                    self.client
                        .query_one("SELECT pg_advisory_unlock($1)", &[&self.lock_key]),
                )?
                .get(0);
            if !unlocked {
                return Err("test completion barrier advisory lock was not held".into());
            }
            self.released = true;
        }
        Ok(())
    }

    fn cleanup(mut self) -> TestResult {
        self.release()?;
        self.runtime.block_on(self.client.execute(
            "DELETE FROM politeia_test_completion_barriers
             WHERE institution_id = $1 AND workspace_id = $2",
            &[&self.institution, &self.workspace],
        ))?;
        self.runtime.block_on(self.client.batch_execute(&format!(
            "DROP TRIGGER IF EXISTS {BARRIER_TRIGGER} ON operation_attempts;
                 DROP FUNCTION IF EXISTS {BARRIER_FUNCTION}();
                 DROP TABLE IF EXISTS {BARRIER_TABLE};",
        )))?;
        Ok(())
    }
}
