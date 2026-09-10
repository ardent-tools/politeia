//! Durable PostgreSQL authority for a client-controlled Politeia workspace.
//!
//! The crate stores canonical records after the host has admitted their semantic
//! meaning. It does not reinterpret authority, policy, or evidence payloads.

#![deny(missing_docs)]

mod read;
pub use read::{PersistedDelegation, StoredPayload, WorkspaceSnapshot};

use std::str::FromStr;

use politeia_runtime::{AuthorizationLedger, ReservationRequest, RuntimeError};

use jiff::Timestamp;

use politeia_core::{
    BudgetReservationId, Delegation, DelegationId, Digest, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PrincipalId, ResourceBudget,
    canonical::to_canonical_bytes,
    institution::TrustDomainId,
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use serde_json::Value;
use tokio_postgres::{Client, Config, IsolationLevel, NoTls};
use uuid::Uuid;

const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_commissioning",
        include_str!("../migrations/0001_commissioning.sql"),
    ),
    (
        "0002_admission_revision",
        include_str!("../migrations/0002_admission_revision.sql"),
    ),
];
const SERIALIZABLE_ATTEMPTS: usize = 3;

/// The three identities that scope every durable storage operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    trust_domain: TrustDomainId,
}

impl Scope {
    /// Name the exact storage scope validated by the service boundary.
    ///
    /// This value identifies a scope; constructing it grants no authority.
    pub fn new(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        trust_domain: TrustDomainId,
    ) -> Self {
        Self {
            institution,
            workspace,
            trust_domain,
        }
    }

    /// Return the institution identity.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// Return the workspace identity.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Return the client-controlled trust domain.
    pub fn trust_domain(&self) -> &TrustDomainId {
        &self.trust_domain
    }
}

/// Canonical bytes signed by an authenticated principal before admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    payload: Vec<u8>,
    digest: Digest,
    signer: PrincipalId,
    signature: Vec<u8>,
}

impl SignedRecord {
    /// Canonicalize a JSON value and retain its content binding and signature.
    ///
    /// Signature verification belongs to the semantic admission boundary; the
    /// storage layer preserves exactly the verified bytes and signer binding.
    pub fn from_json(
        value: &Value,
        signer: PrincipalId,
        signature: Vec<u8>,
    ) -> Result<Self, StorageError> {
        let payload =
            politeia_core::canonical::to_canonical_bytes(value).map_err(StorageError::Canonical)?;
        Ok(Self {
            digest: Digest::blake3(&payload),
            payload,
            signer,
            signature,
        })
    }

    /// Validate an already canonical payload against its supplied digest.
    pub fn from_bytes(
        payload: Vec<u8>,
        digest: Digest,
        signer: PrincipalId,
        signature: Vec<u8>,
    ) -> Result<Self, StorageError> {
        let actual = Digest::blake3(&payload);
        if actual != digest {
            return Err(StorageError::DigestMismatch {
                expected: digest,
                actual,
            });
        }
        Ok(Self {
            payload,
            digest,
            signer,
            signature,
        })
    }

    /// Return the immutable canonical bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Return the digest of the stored bytes.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Return the principal that signed the record.
    pub fn signer(&self) -> &PrincipalId {
        &self.signer
    }

    /// Return the detached signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// The owner-approved initial workspace model.
#[derive(Clone, Debug)]
pub struct WorkspaceBootstrap {
    /// Scope of the new workspace.
    pub scope: Scope,
    /// Owner responsible for the workspace.
    pub owner: PrincipalId,
    /// Owner delegation that authorizes the workspace record.
    pub owner_delegation: DelegationId,
    /// Signed canonical model bytes.
    pub model: SignedRecord,
}

/// One evidence record, identified by the core evidence identity.
#[derive(Clone, Debug)]
pub struct EvidenceAdmission {
    /// Stable evidence identity.
    pub id: EvidenceId,
    /// Signed canonical evidence payload.
    pub record: SignedRecord,
}

/// One state key changed by an approved workspace revision.
#[derive(Clone, Debug)]
pub struct StateMutation {
    /// Stable normalized state key.
    pub key: String,
    /// Canonical value stored for the current state projection.
    pub value: SignedRecord,
}

/// An outbox message published only after its enclosing transaction commits.
#[derive(Clone, Debug)]
pub struct OutboxMessage {
    /// Stable message identity supplied by the caller.
    pub id: Uuid,
    /// Declared destination/topic class.
    pub topic: String,
    /// Canonical payload to deliver.
    pub payload: SignedRecord,
}

/// A compare-and-swap approved-model transition and its immutable evidence.
#[derive(Clone, Debug)]
pub struct ScopedCommit {
    /// Scope of the state transition.
    pub scope: Scope,
    /// Current revision the service previously observed.
    pub expected_revision: i64,
    /// New owner-approved model revision.
    pub model: SignedRecord,
    /// Semantic record kind for the revision history.
    pub model_kind: String,
    /// Immutable transition journal record.
    pub transition: SignedRecord,
    /// Current-state projections changed by this transition.
    pub state: Vec<StateMutation>,
    /// Evidence admitted with this transition.
    pub evidence: Vec<EvidenceAdmission>,
    /// External messages committed transactionally with this transition.
    pub outbox: Vec<OutboxMessage>,
}

/// The newly committed workspace revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Monotonic revision after the successful compare-and-swap.
    pub revision: i64,
    /// Digest of the transition appended to the journal.
    pub transition_digest: Digest,
}

/// A signed immutable runtime-generation manifest and its bound artifacts.
#[derive(Clone, Debug)]
pub struct RuntimeGeneration {
    /// Scope that owns the generation.
    pub scope: Scope,
    /// Content identity of the complete generation.
    pub generation_digest: Digest,
    /// Digest of all specialization inputs.
    pub input_digest: Digest,
    /// Digest of the generated artifact bytes.
    pub artifact_digest: Digest,
    /// Signed canonical generation manifest.
    pub manifest: SignedRecord,
}

/// One compare-and-swap activation transition for an admitted generation.
#[derive(Clone, Debug)]
pub struct ActivationCommit {
    /// Scope whose active generation changes.
    pub scope: Scope,
    /// Workspace revision observed before activation.
    pub expected_revision: i64,
    /// Active generation observed before activation, including an explicit empty state.
    pub expected_active: Option<Digest>,
    /// Already-admitted generation to make active.
    pub generation: Digest,
    /// Immutable transition record that binds the activation.
    pub transition: SignedRecord,
    /// Evidence admitted with activation.
    pub evidence: Vec<EvidenceAdmission>,
    /// External messages committed with activation.
    pub outbox: Vec<OutboxMessage>,
}

/// One durable operation reservation before an effect port can run.
#[derive(Clone, Debug)]
pub struct AttemptReservation {
    /// Scope that owns replay and attempt state.
    pub scope: Scope,
    /// Dispatcher-created reservation identity.
    pub reservation_id: BudgetReservationId,
    /// Isolation domain for replay and delegation budget accounts.
    pub replay_domain: String,
    /// Exact semantic replay subject.
    pub replay_key: Digest,
    /// Digest of the immutable lease claims.
    pub claims_digest: Digest,
    /// Whether completed replay state remains retained beyond lease expiry.
    pub retain_replay: bool,
    /// Canonical lease/reservation payload.
    pub request_payload: Vec<u8>,
    /// RFC 3339 timestamp at which the reservation ceases to be claimable.
    pub expires_at: String,
}

/// The durable state of a protected operation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttemptStatus {
    /// Reserved before a lease is returned.
    Reserved,
    /// Claimed exactly once immediately before effect-port invocation.
    Claimed,
    /// Completed after a bound execution receipt was admitted.
    Completed,
}

/// A row read from the durable attempt ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// Current durable attempt state.
    pub status: AttemptStatus,
    /// Optional execution-receipt digest; absent means outcome remains unresolved.
    pub receipt_digest: Option<Digest>,
}

/// A persisted outbox message ready for a delivery worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOutbox {
    /// Scope owning the message.
    pub scope: Scope,
    /// Stable outbox identity.
    pub id: Uuid,
    /// Declared delivery topic.
    pub topic: String,
    /// Canonical immutable delivery bytes.
    pub payload: Vec<u8>,
    /// Digest of the delivery bytes.
    pub payload_digest: Digest,
}

/// Errors emitted by the durable storage boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// PostgreSQL rejected or interrupted an operation.
    Database(tokio_postgres::Error),
    /// A JSON value could not be canonicalized.
    Canonical(politeia_core::canonical::CanonicalError),
    /// Supplied bytes and digest do not bind the same value.
    DigestMismatch {
        /// Caller-supplied digest.
        expected: Digest,
        /// Digest computed from supplied bytes.
        actual: Digest,
    },
    /// A signed wire envelope did not match the anchor-admitted semantic value.
    AdmissionMismatch,
    /// A compare-and-swap observed a different workspace revision.
    RevisionConflict,
    /// A required scoped record is absent.
    NotFound,
    /// An immutable identity already names different content.
    ImmutableConflict,
    /// An operation attempt cannot perform the requested state transition.
    AttemptUnavailable,
    /// PostgreSQL kept aborting serializable transactions.
    SerializationExhausted,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(source) => write!(formatter, "PostgreSQL operation failed: {source}"),
            Self::Canonical(source) => write!(formatter, "canonical encoding failed: {source}"),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "record digest mismatch: expected {}, computed {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::AdmissionMismatch => {
                formatter.write_str("signed admission does not match its admitted value")
            }
            Self::RevisionConflict => {
                formatter.write_str("workspace revision changed concurrently")
            }
            Self::NotFound => formatter.write_str("scoped record was not found"),
            Self::ImmutableConflict => {
                formatter.write_str("immutable identity already names other content")
            }
            Self::AttemptUnavailable => {
                formatter.write_str("attempt is missing, expired, replayed, or not claimable")
            }
            Self::SerializationExhausted => {
                formatter.write_str("serializable transaction retry budget exhausted")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::Canonical(source) => Some(source),
            Self::DigestMismatch { .. }
            | Self::AdmissionMismatch
            | Self::RevisionConflict
            | Self::NotFound
            | Self::ImmutableConflict
            | Self::AttemptUnavailable
            | Self::SerializationExhausted => None,
        }
    }
}

/// PostgreSQL-backed durable authority outside the semantic kernel.
#[derive(Clone, Debug)]
pub struct PostgresStorage {
    config: Config,
}

impl PostgresStorage {
    /// Parse and verify a PostgreSQL connection string.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let config = Config::from_str(database_url).map_err(StorageError::Database)?;
        let storage = Self { config };
        let _client = storage.client().await?;
        Ok(storage)
    }

    /// Apply the versioned PostgreSQL schema migrations.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS politeia_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            )
            .await
            .map_err(StorageError::Database)?;
        for (name, sql) in MIGRATIONS {
            let exists = client
                .query_opt(
                    "SELECT 1 FROM politeia_schema_migrations WHERE name = $1",
                    &[name],
                )
                .await
                .map_err(StorageError::Database)?;
            if exists.is_none() {
                let transaction = client
                    .build_transaction()
                    .isolation_level(IsolationLevel::Serializable)
                    .start()
                    .await
                    .map_err(StorageError::Database)?;
                transaction
                    .batch_execute(sql)
                    .await
                    .map_err(StorageError::Database)?;
                transaction
                    .execute(
                        "INSERT INTO politeia_schema_migrations (name) VALUES ($1)",
                        &[name],
                    )
                    .await
                    .map_err(StorageError::Database)?;
                transaction.commit().await.map_err(StorageError::Database)?;
            }
        }
        Ok(())
    }

    /// Create a workspace once, preserving its signed initial model.
    pub async fn bootstrap_workspace(
        &self,
        bootstrap: &WorkspaceBootstrap,
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await.map_err(StorageError::Database)?;
        let scope = scope_values(&bootstrap.scope);
        let inserted = transaction
            .execute(
                "INSERT INTO institution_workspaces (institution_id, workspace_id, trust_domain, owner_principal_id, owner_delegation_id, model_digest, model_payload, model_signature, model_signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
                &[
                    &scope.institution,
                    &scope.workspace,
                    &scope.trust_domain,
                    &bootstrap.owner.0,
                    &bootstrap.owner_delegation.0,
                    &bootstrap.model.digest().as_str(),
                    &bootstrap.model.payload(),
                    &bootstrap.model.signature(),
                    &bootstrap.model.signer().0,
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        if inserted == 0 {
            return Err(StorageError::ImmutableConflict);
        }
        transaction.execute(
            "INSERT INTO workspace_revisions (institution_id, workspace_id, revision, record_kind, content_digest, payload, signature, signer_id) VALUES ($1, $2, 0, 'workspace_bootstrap', $3, $4, $5, $6)",
            &[&scope.institution, &scope.workspace, &bootstrap.model.digest().as_str(), &bootstrap.model.payload(), &bootstrap.model.signature(), &bootstrap.model.signer().0],
        ).await.map_err(StorageError::Database)?;
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    /// Atomically compare-and-swap the approved model, state, journals, and outbox.
    pub async fn commit(&self, commit: &ScopedCommit) -> Result<CommitReceipt, StorageError> {
        for attempt in 0..SERIALIZABLE_ATTEMPTS {
            match self.commit_once(commit).await {
                Err(StorageError::Database(source))
                    if is_serialization_failure(&source) && attempt + 1 < SERIALIZABLE_ATTEMPTS => {
                }
                outcome => return outcome,
            }
        }
        Err(StorageError::SerializationExhausted)
    }

    /// Persist an anchor-admitted delegation and its exact signed wire envelope.
    pub async fn admit_delegation(
        &self,
        scope: &Scope,
        admitted: &Admitted<Delegation>,
        wire: &SignedAdmissionWire<Delegation>,
    ) -> Result<(), StorageError> {
        if admitted.kind() != AdmissionKind::Delegation
            || admitted.institution() != scope.institution()
            || admitted.workspace() != scope.workspace()
            || wire.institution != *scope.institution()
            || wire.workspace != *scope.workspace()
            || wire.signer != *admitted.signer()
            || to_canonical_bytes(&wire.payload).map_err(StorageError::Canonical)?
                != to_canonical_bytes(admitted.payload()).map_err(StorageError::Canonical)?
        {
            return Err(StorageError::AdmissionMismatch);
        }
        let delegation = admitted.payload();
        let delegation_payload = to_canonical_bytes(delegation).map_err(StorageError::Canonical)?;
        let delegation_digest = Digest::blake3(&delegation_payload);
        let wire_payload = to_canonical_bytes(wire).map_err(StorageError::Canonical)?;
        let wire_digest = Digest::blake3(&wire_payload);
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let inserted = client.execute(
            "INSERT INTO delegations (institution_id, workspace_id, delegation_id, delegation_digest, wire_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &delegation.id.0, &delegation_digest.as_str(), &wire_digest.as_str(), &wire_payload, &wire.signature, &wire.signer.0],
        ).await.map_err(StorageError::Database)?;
        if inserted == 0 {
            return Err(StorageError::ImmutableConflict);
        }
        Ok(())
    }

    /// Record a delegation revocation once with its admitted evidence identity.
    pub async fn revoke_delegation(
        &self,
        scope: &Scope,
        delegation: &DelegationId,
        revocation_digest: &Digest,
        evidence: &EvidenceId,
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let admitted = transaction.query_opt(
            "SELECT 1 FROM delegations d JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE d.institution_id = $1 AND d.workspace_id = $2 AND d.delegation_id = $3 AND w.trust_domain = $4 FOR UPDATE OF d",
            &[&scoped.institution, &scoped.workspace, &delegation.0, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?;
        if admitted.is_none() {
            return Err(StorageError::NotFound);
        }
        let inserted = transaction.execute(
            "INSERT INTO delegation_revocations (institution_id, workspace_id, delegation_id, revocation_digest, evidence_record_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &delegation.0, &revocation_digest.as_str(), &evidence.0],
        ).await.map_err(StorageError::Database)?;
        if inserted == 0 {
            return Err(StorageError::ImmutableConflict);
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    /// Admit a signed immutable generation before activation.
    pub async fn admit_generation(
        &self,
        generation: &RuntimeGeneration,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(&generation.scope);
        let inserted = client.execute(
            "INSERT INTO runtime_generations (institution_id, workspace_id, generation_digest, input_digest, artifact_digest, manifest, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &generation.generation_digest.as_str(), &generation.input_digest.as_str(), &generation.artifact_digest.as_str(), &generation.manifest.payload(), &generation.manifest.signature(), &generation.manifest.signer().0],
        ).await.map_err(StorageError::Database)?;
        if inserted == 0 {
            return Err(StorageError::ImmutableConflict);
        }
        Ok(())
    }

    /// Recover one immutable generation envelope within the installed scope.
    ///
    /// The returned manifest remains inert until the semantic service re-admits
    /// its signed generation inputs and verifies the associated artifact bytes.
    pub async fn load_generation(
        &self,
        scope: &Scope,
        generation_digest: &Digest,
    ) -> Result<RuntimeGeneration, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let row = client
            .query_opt(
                "SELECT g.input_digest, g.artifact_digest, g.manifest, g.signature, g.signer_id FROM runtime_generations g JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE g.institution_id = $1 AND g.workspace_id = $2 AND w.trust_domain = $3 AND g.generation_digest = $4",
                &[&scoped.institution, &scoped.workspace, &scoped.trust_domain, &generation_digest.as_str()],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::NotFound)?;
        let manifest_bytes: Vec<u8> = row.get(2);
        let manifest = SignedRecord::from_bytes(
            manifest_bytes.clone(),
            Digest::blake3(&manifest_bytes),
            PrincipalId(row.get(4)),
            row.get(3),
        )?;
        Ok(RuntimeGeneration {
            scope: scope.clone(),
            generation_digest: generation_digest.clone(),
            input_digest: parse_digest(&row.get::<_, String>(0))?,
            artifact_digest: parse_digest(&row.get::<_, String>(1))?,
            manifest,
        })
    }

    /// Atomically compare-and-swap the active generation and append its evidence-bearing transition.
    pub async fn activate_generation(
        &self,
        activation: &ActivationCommit,
    ) -> Result<CommitReceipt, StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(&activation.scope);
        let generation_exists = transaction.query_opt(
            "SELECT 1 FROM runtime_generations WHERE institution_id = $1 AND workspace_id = $2 AND generation_digest = $3 FOR KEY SHARE",
            &[&scoped.institution, &scoped.workspace, &activation.generation.as_str()],
        ).await.map_err(StorageError::Database)?;
        if generation_exists.is_none() {
            return Err(StorageError::NotFound);
        }
        let next_revision = activation
            .expected_revision
            .checked_add(1)
            .ok_or(StorageError::RevisionConflict)?;
        let expected_active = activation.expected_active.as_ref().map(Digest::as_str);
        let updated = transaction.execute(
            "UPDATE institution_workspaces SET active_generation_digest = $4, revision = $5, updated_at = CURRENT_TIMESTAMP WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 AND revision = $6 AND active_generation_digest IS NOT DISTINCT FROM $7",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain, &activation.generation.as_str(), &next_revision, &activation.expected_revision, &expected_active],
        ).await.map_err(StorageError::Database)?;
        if updated != 1 {
            return Err(StorageError::RevisionConflict);
        }
        let previous = transaction.query_opt(
            "SELECT transition_digest FROM transition_journal WHERE institution_id = $1 AND workspace_id = $2 ORDER BY sequence DESC LIMIT 1 FOR KEY SHARE",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)?.map(|row| row.get::<_, String>(0));
        transaction.execute(
            "INSERT INTO transition_journal (institution_id, workspace_id, transition_digest, previous_digest, payload) VALUES ($1, $2, $3, $4, $5)",
            &[&scoped.institution, &scoped.workspace, &activation.transition.digest().as_str(), &previous, &activation.transition.payload()],
        ).await.map_err(StorageError::Database)?;
        for evidence in &activation.evidence {
            transaction.execute(
                "INSERT INTO evidence_journal (institution_id, workspace_id, evidence_id, evidence_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[&scoped.institution, &scoped.workspace, &evidence.id.0, &evidence.record.digest().as_str(), &evidence.record.payload(), &evidence.record.signature(), &evidence.record.signer().0],
            ).await.map_err(StorageError::Database)?;
        }
        for message in &activation.outbox {
            transaction.execute(
                "INSERT INTO transactional_outbox (institution_id, workspace_id, outbox_id, topic, payload, payload_digest) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&scoped.institution, &scoped.workspace, &message.id, &message.topic, &message.payload.payload(), &message.payload.digest().as_str()],
            ).await.map_err(StorageError::Database)?;
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(CommitReceipt {
            revision: next_revision,
            transition_digest: activation.transition.digest().clone(),
        })
    }

    /// Reserve an exact replay subject before a dispatcher returns an effect lease.
    pub async fn reserve_attempt(
        &self,
        reservation: &AttemptReservation,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(&reservation.scope);
        let inserted = client.execute(
            "INSERT INTO operation_attempts (institution_id, workspace_id, reservation_id, replay_domain, replay_key, claims_digest, retain_replay, request_payload, expires_at) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9::text::timestamptz WHERE EXISTS (SELECT 1 FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $10) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &reservation.reservation_id.0, &reservation.replay_domain, &reservation.replay_key.as_str(), &reservation.claims_digest.as_str(), &reservation.retain_replay, &reservation.request_payload, &reservation.expires_at, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?;
        if inserted != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        Ok(())
    }

    /// Atomically consume a reservation immediately before an effect port runs.
    pub async fn claim_attempt(
        &self,
        scope: &Scope,
        reservation: &BudgetReservationId,
        claims: &Digest,
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let claimed = transaction.execute(
            "UPDATE operation_attempts SET status = 'claimed' WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3 AND claims_digest = $4 AND status = 'reserved' AND expires_at > CURRENT_TIMESTAMP",
            &[&scoped.institution, &scoped.workspace, &reservation.0, &claims.as_str()],
        ).await.map_err(StorageError::Database)?;
        if claimed != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    /// Persist an execution receipt only after an effect port has returned it.
    pub async fn record_completion(
        &self,
        scope: &Scope,
        reservation: &BudgetReservationId,
        receipt: &Digest,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let completed = client.execute(
            "UPDATE operation_attempts a SET status = 'completed', receipt_digest = $4, completed_at = CURRENT_TIMESTAMP FROM institution_workspaces w WHERE a.institution_id = $1 AND a.workspace_id = $2 AND a.reservation_id = $3 AND a.status = 'claimed' AND w.institution_id = a.institution_id AND w.workspace_id = a.workspace_id AND w.trust_domain = $5",
            &[&scoped.institution, &scoped.workspace, &reservation.0, &receipt.as_str(), &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?;
        if completed != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        Ok(())
    }

    /// Read an attempt without translating an absent receipt into an outcome.
    pub async fn load_attempt(
        &self,
        scope: &Scope,
        reservation: &BudgetReservationId,
    ) -> Result<Attempt, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let row = client.query_opt(
            "SELECT a.status::text, a.receipt_digest FROM operation_attempts a JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE a.institution_id = $1 AND a.workspace_id = $2 AND a.reservation_id = $3 AND w.trust_domain = $4",
            &[&scoped.institution, &scoped.workspace, &reservation.0, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        let status = match row.get::<_, String>(0).as_str() {
            "reserved" => AttemptStatus::Reserved,
            "claimed" => AttemptStatus::Claimed,
            "completed" => AttemptStatus::Completed,
            _ => return Err(StorageError::ImmutableConflict),
        };
        let receipt = row
            .get::<_, Option<String>>(1)
            .map(|value| parse_digest(&value))
            .transpose()?;
        Ok(Attempt {
            status,
            receipt_digest: receipt,
        })
    }

    /// Read one active generation digest within the supplied scope.
    pub async fn load_active_generation(
        &self,
        scope: &Scope,
    ) -> Result<Option<Digest>, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let row = client.query_opt(
            "SELECT active_generation_digest FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        row.get::<_, Option<String>>(0)
            .map(|value| parse_digest(&value))
            .transpose()
    }

    /// Acquire undelivered outbox rows; delivery confirmation is recorded separately.
    pub async fn take_outbox(
        &self,
        scope: &Scope,
        limit: i64,
    ) -> Result<Vec<PendingOutbox>, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let rows = client.query(
            "SELECT outbox_id, topic, payload, payload_digest FROM transactional_outbox WHERE institution_id = $1 AND workspace_id = $2 AND delivered_at IS NULL AND available_at <= CURRENT_TIMESTAMP ORDER BY available_at, outbox_id LIMIT $3",
            &[&scoped.institution, &scoped.workspace, &limit],
        ).await.map_err(StorageError::Database)?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingOutbox {
                    scope: scope.clone(),
                    id: row.get(0),
                    topic: row.get(1),
                    payload: row.get(2),
                    payload_digest: parse_digest(&row.get::<_, String>(3))?,
                })
            })
            .collect()
    }

    /// Mark one delivered outbox row after the delivery worker has evidence of publication.
    pub async fn mark_outbox_delivered(&self, scope: &Scope, id: Uuid) -> Result<(), StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let updated = client.execute(
            "UPDATE transactional_outbox SET delivered_at = CURRENT_TIMESTAMP WHERE institution_id = $1 AND workspace_id = $2 AND outbox_id = $3 AND delivered_at IS NULL",
            &[&scoped.institution, &scoped.workspace, &id],
        ).await.map_err(StorageError::Database)?;
        if updated != 1 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn client(&self) -> Result<Client, StorageError> {
        let (client, connection) = self
            .config
            .connect(NoTls)
            .await
            .map_err(StorageError::Database)?;
        tokio::spawn(async move {
            let _result = connection.await;
        });
        Ok(client)
    }

    async fn commit_once(&self, commit: &ScopedCommit) -> Result<CommitReceipt, StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(&commit.scope);
        let next_revision = commit
            .expected_revision
            .checked_add(1)
            .ok_or(StorageError::RevisionConflict)?;
        let updated = transaction.execute(
            "UPDATE institution_workspaces SET revision = $4, model_digest = $5, model_payload = $6, model_signature = $7, model_signer_id = $8, updated_at = CURRENT_TIMESTAMP WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 AND revision = $9",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain, &next_revision, &commit.model.digest().as_str(), &commit.model.payload(), &commit.model.signature(), &commit.model.signer().0, &commit.expected_revision],
        ).await.map_err(StorageError::Database)?;
        if updated != 1 {
            return Err(StorageError::RevisionConflict);
        }
        transaction.execute(
            "INSERT INTO workspace_revisions (institution_id, workspace_id, revision, record_kind, content_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&scoped.institution, &scoped.workspace, &next_revision, &commit.model_kind, &commit.model.digest().as_str(), &commit.model.payload(), &commit.model.signature(), &commit.model.signer().0],
        ).await.map_err(StorageError::Database)?;
        let previous = transaction.query_opt(
            "SELECT transition_digest FROM transition_journal WHERE institution_id = $1 AND workspace_id = $2 ORDER BY sequence DESC LIMIT 1 FOR KEY SHARE",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)?.map(|row| row.get::<_, String>(0));
        transaction.execute(
            "INSERT INTO transition_journal (institution_id, workspace_id, transition_digest, previous_digest, payload) VALUES ($1, $2, $3, $4, $5)",
            &[&scoped.institution, &scoped.workspace, &commit.transition.digest().as_str(), &previous, &commit.transition.payload()],
        ).await.map_err(StorageError::Database)?;
        for state in &commit.state {
            transaction.execute(
                "INSERT INTO state_entries (institution_id, workspace_id, state_key, value_digest, value_payload) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (institution_id, workspace_id, state_key) DO UPDATE SET value_digest = EXCLUDED.value_digest, value_payload = EXCLUDED.value_payload, updated_at = CURRENT_TIMESTAMP",
                &[&scoped.institution, &scoped.workspace, &state.key, &state.value.digest().as_str(), &state.value.payload()],
            ).await.map_err(StorageError::Database)?;
        }
        for evidence in &commit.evidence {
            transaction.execute(
                "INSERT INTO evidence_journal (institution_id, workspace_id, evidence_id, evidence_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[&scoped.institution, &scoped.workspace, &evidence.id.0, &evidence.record.digest().as_str(), &evidence.record.payload(), &evidence.record.signature(), &evidence.record.signer().0],
            ).await.map_err(StorageError::Database)?;
        }
        for message in &commit.outbox {
            transaction.execute(
                "INSERT INTO transactional_outbox (institution_id, workspace_id, outbox_id, topic, payload, payload_digest) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&scoped.institution, &scoped.workspace, &message.id, &message.topic, &message.payload.payload(), &message.payload.digest().as_str()],
            ).await.map_err(StorageError::Database)?;
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(CommitReceipt {
            revision: next_revision,
            transition_digest: commit.transition.digest().clone(),
        })
    }
}

/// A scope-bound, restart-durable implementation of the runtime authorization ledger.
///
/// It admits only delegation digests already stored in the same PostgreSQL
/// workspace, so a daemon cannot nominate a foreign or revoked authority by
/// constructing a different [`Scope`].
#[derive(Clone, Debug)]
pub struct PostgresAuthorizationLedger {
    storage: PostgresStorage,
    scope: Scope,
    bootstrap: Option<Digest>,
}

impl PostgresAuthorizationLedger {
    /// Bind the ledger to the active generation of one persisted workspace.
    ///
    /// Reserve and claim both compare the lease generation under a shared
    /// workspace-row lock, serializing them with generation activation.
    pub fn new(storage: PostgresStorage, scope: Scope) -> Self {
        Self {
            storage,
            scope,
            bootstrap: None,
        }
    }

    /// Bind initial commissioning to the immutable owner-signed bootstrap.
    ///
    /// The trusted host supplies the canonical signed bootstrap record digest
    /// as the dispatcher runtime identity. This mode refuses once any runtime
    /// generation is active, and checks revision zero rather than the mutable
    /// model. It supplies no policy permission: the dispatcher must still
    /// authorize the exact commissioning operation and all grant axes.
    pub fn for_bootstrap(storage: PostgresStorage, scope: Scope, bootstrap: Digest) -> Self {
        Self {
            storage,
            scope,
            bootstrap: Some(bootstrap),
        }
    }

    /// Return the exact workspace authority domain this ledger serves.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl AuthorizationLedger for PostgresAuthorizationLedger {
    async fn observed_at(&self) -> Result<Timestamp, RuntimeError> {
        let client = self.storage.client().await.map_err(runtime_state_error)?;
        let row = client
            .query_one("SELECT CURRENT_TIMESTAMP::text", &[])
            .await
            .map_err(|error| runtime_state_error(StorageError::Database(error)))?;
        row.get::<_, String>(0)
            .parse()
            .map_err(|error| RuntimeError::AuthorizationState {
                source: Box::new(error),
            })
    }

    async fn reserve(&self, request: &ReservationRequest) -> Result<(), RuntimeError> {
        self.storage
            .reserve_runtime_request(&self.scope, request, self.bootstrap.as_ref())
            .await
            .map_err(runtime_state_error)
    }

    async fn claim(&self, request: &ReservationRequest) -> Result<(), RuntimeError> {
        self.storage
            .claim_runtime_request(&self.scope, request, self.bootstrap.as_ref())
            .await
            .map_err(runtime_state_error)
    }
}

impl PostgresStorage {
    async fn reserve_runtime_request(
        &self,
        scope: &Scope,
        request: &ReservationRequest,
        bootstrap: Option<&Digest>,
    ) -> Result<(), StorageError> {
        if !request.requested_budget().is_finite() || request.budget_scopes().is_empty() {
            return Err(StorageError::AttemptUnavailable);
        }
        let requested = BudgetAmounts::from_budget(request.requested_budget())?;
        let payload = serde_json::to_value(request).map_err(|error| {
            StorageError::Canonical(politeia_core::canonical::CanonicalError::Encoding(error))
        })?;
        let payload = politeia_core::canonical::to_canonical_bytes(&payload)
            .map_err(StorageError::Canonical)?;
        for attempt in 0..SERIALIZABLE_ATTEMPTS {
            match self
                .reserve_runtime_once(scope, request, &requested, &payload, bootstrap)
                .await
            {
                Err(StorageError::Database(source))
                    if is_serialization_failure(&source) && attempt + 1 < SERIALIZABLE_ATTEMPTS => {
                }
                outcome => return outcome,
            }
        }
        Err(StorageError::SerializationExhausted)
    }

    async fn reserve_runtime_once(
        &self,
        scope: &Scope,
        request: &ReservationRequest,
        requested: &BudgetAmounts,
        payload: &[u8],
        bootstrap: Option<&Digest>,
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let admission_revision = check_generation(&transaction, scope, request, bootstrap).await?;
        transaction
            .execute(
                "DELETE FROM operation_attempts WHERE institution_id = $1 AND workspace_id = $2 AND replay_domain = $3 AND expires_at <= CURRENT_TIMESTAMP AND (status = 'reserved' OR (status = 'completed' AND retain_replay = FALSE))",
                &[&scoped.institution, &scoped.workspace, &request.replay_domain()],
            )
            .await
            .map_err(StorageError::Database)?;
        for budget_scope in request.budget_scopes() {
            if !request
                .requested_budget()
                .is_attenuation_of(budget_scope.limit())
            {
                return Err(StorageError::AttemptUnavailable);
            }
            let admitted = transaction
                .query_opt(
                    "SELECT d.delegation_digest FROM delegations d LEFT JOIN delegation_revocations r ON r.institution_id = d.institution_id AND r.workspace_id = d.workspace_id AND r.delegation_id = d.delegation_id WHERE d.institution_id = $1 AND d.workspace_id = $2 AND d.delegation_id = $3 AND r.delegation_id IS NULL FOR KEY SHARE OF d",
                    &[&scoped.institution, &scoped.workspace, &budget_scope.delegation_id().0],
                )
                .await
                .map_err(StorageError::Database)?;
            let Some(admitted) = admitted else {
                return Err(StorageError::AttemptUnavailable);
            };
            if admitted.get::<_, String>(0) != budget_scope.delegation_digest().as_str() {
                return Err(StorageError::AttemptUnavailable);
            }
            let limit = BudgetLimits::from_budget(budget_scope.limit());
            let limit_values = limit.as_strings();
            transaction
                .execute(
                    "INSERT INTO delegation_budget_accounts (institution_id, workspace_id, replay_domain, delegation_id, delegation_digest, wall_ms_limit, cpu_ms_limit, memory_bytes_limit, io_bytes_limit, network_bytes_limit, external_cost_microunits_limit) VALUES ($1, $2, $3, $4, $5, $6::text::numeric, $7::text::numeric, $8::text::numeric, $9::text::numeric, $10::text::numeric, $11::text::numeric) ON CONFLICT DO NOTHING",
                    &[&scoped.institution, &scoped.workspace, &request.replay_domain(), &budget_scope.delegation_id().0, &budget_scope.delegation_digest().as_str(), &limit_values.0, &limit_values.1, &limit_values.2, &limit_values.3, &limit_values.4, &limit_values.5],
                )
                .await
                .map_err(StorageError::Database)?;
            let account = transaction
                .query_one(
                    "SELECT delegation_digest, wall_ms_limit::text, cpu_ms_limit::text, memory_bytes_limit::text, io_bytes_limit::text, network_bytes_limit::text, external_cost_microunits_limit::text, wall_ms_committed::text, cpu_ms_committed::text, memory_bytes_committed::text, io_bytes_committed::text, network_bytes_committed::text, external_cost_microunits_committed::text FROM delegation_budget_accounts WHERE institution_id = $1 AND workspace_id = $2 AND replay_domain = $3 AND delegation_id = $4 FOR UPDATE",
                    &[&scoped.institution, &scoped.workspace, &request.replay_domain(), &budget_scope.delegation_id().0],
                )
                .await
                .map_err(StorageError::Database)?;
            if account.get::<_, String>(0) != budget_scope.delegation_digest().as_str()
                || BudgetLimits::from_row(&account, 1)? != limit
            {
                return Err(StorageError::AttemptUnavailable);
            }
            let pending = transaction
                .query_one(
                    "SELECT COALESCE(SUM(s.wall_ms), 0)::text, COALESCE(SUM(s.cpu_ms), 0)::text, COALESCE(SUM(s.memory_bytes), 0)::text, COALESCE(SUM(s.io_bytes), 0)::text, COALESCE(SUM(s.network_bytes), 0)::text, COALESCE(SUM(s.external_cost_microunits), 0)::text FROM attempt_budget_scopes s JOIN operation_attempts a ON a.institution_id = s.institution_id AND a.workspace_id = s.workspace_id AND a.reservation_id = s.reservation_id WHERE s.institution_id = $1 AND s.workspace_id = $2 AND s.replay_domain = $3 AND s.delegation_id = $4 AND a.status = 'reserved' AND a.expires_at > CURRENT_TIMESTAMP",
                    &[&scoped.institution, &scoped.workspace, &request.replay_domain(), &budget_scope.delegation_id().0],
                )
                .await
                .map_err(StorageError::Database)?;
            let committed = BudgetAmounts::from_row(&account, 7)?;
            let pending = BudgetAmounts::from_row(&pending, 0)?;
            if !requested.fits(limit, committed.checked_add(pending)?) {
                return Err(StorageError::AttemptUnavailable);
            }
        }
        let expires_at = request.expires_at().to_string();
        let requested_values = requested.as_strings();
        let inserted = transaction
            .execute(
                "INSERT INTO operation_attempts (institution_id, workspace_id, reservation_id, replay_domain, replay_key, claims_digest, retain_replay, request_payload, expires_at, admission_revision) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::timestamptz, $10) ON CONFLICT DO NOTHING",
                &[&scoped.institution, &scoped.workspace, &request.reservation_id().0, &request.replay_domain(), &request.replay_key().as_str(), &request.claims_digest().as_str(), &request.retains_replay(), &payload, &expires_at, &admission_revision],
            )
            .await
            .map_err(StorageError::Database)?;
        if inserted != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        for budget_scope in request.budget_scopes() {
            transaction
                .execute(
                    "INSERT INTO attempt_budget_scopes (institution_id, workspace_id, reservation_id, replay_domain, delegation_id, wall_ms, cpu_ms, memory_bytes, io_bytes, network_bytes, external_cost_microunits) VALUES ($1, $2, $3, $4, $5, $6::text::numeric, $7::text::numeric, $8::text::numeric, $9::text::numeric, $10::text::numeric, $11::text::numeric)",
                    &[&scoped.institution, &scoped.workspace, &request.reservation_id().0, &request.replay_domain(), &budget_scope.delegation_id().0, &requested_values.0, &requested_values.1, &requested_values.2, &requested_values.3, &requested_values.4, &requested_values.5],
                )
                .await
                .map_err(StorageError::Database)?;
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    async fn claim_runtime_request(
        &self,
        scope: &Scope,
        request: &ReservationRequest,
        bootstrap: Option<&Digest>,
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let admission_revision = check_generation(&transaction, scope, request, bootstrap).await?;
        for budget_scope in request.budget_scopes() {
            let admitted = transaction
                .query_opt(
                    "SELECT d.delegation_digest FROM delegations d LEFT JOIN delegation_revocations r ON r.institution_id = d.institution_id AND r.workspace_id = d.workspace_id AND r.delegation_id = d.delegation_id WHERE d.institution_id = $1 AND d.workspace_id = $2 AND d.delegation_id = $3 AND r.delegation_id IS NULL FOR UPDATE OF d",
                    &[&scoped.institution, &scoped.workspace, &budget_scope.delegation_id().0],
                )
                .await
                .map_err(StorageError::Database)?;
            if admitted.is_none_or(|row| {
                row.get::<_, String>(0) != budget_scope.delegation_digest().as_str()
            }) {
                return Err(StorageError::AttemptUnavailable);
            }
        }
        let claimed = transaction
            .execute(
                "UPDATE operation_attempts SET status = 'claimed' WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3 AND replay_domain = $4 AND replay_key = $5 AND claims_digest = $6 AND status = 'reserved' AND expires_at > CURRENT_TIMESTAMP AND admission_revision = $7",
                &[&scoped.institution, &scoped.workspace, &request.reservation_id().0, &request.replay_domain(), &request.replay_key().as_str(), &request.claims_digest().as_str(), &admission_revision],
            )
            .await
            .map_err(StorageError::Database)?;
        if claimed != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        for budget_scope in request.budget_scopes() {
            let requested = BudgetAmounts::from_budget(request.requested_budget())?;
            let requested_values = requested.as_strings();
            let updated = transaction
                .execute(
                    "UPDATE delegation_budget_accounts SET wall_ms_committed = wall_ms_committed + $5::text::numeric, cpu_ms_committed = cpu_ms_committed + $6::text::numeric, memory_bytes_committed = memory_bytes_committed + $7::text::numeric, io_bytes_committed = io_bytes_committed + $8::text::numeric, network_bytes_committed = network_bytes_committed + $9::text::numeric, external_cost_microunits_committed = external_cost_microunits_committed + $10::text::numeric WHERE institution_id = $1 AND workspace_id = $2 AND replay_domain = $3 AND delegation_id = $4 AND delegation_digest = $11",
                    &[&scoped.institution, &scoped.workspace, &request.replay_domain(), &budget_scope.delegation_id().0, &requested_values.0, &requested_values.1, &requested_values.2, &requested_values.3, &requested_values.4, &requested_values.5, &budget_scope.delegation_digest().as_str()],
                )
                .await
                .map_err(StorageError::Database)?;
            if updated != 1 {
                return Err(StorageError::AttemptUnavailable);
            }
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }
}

async fn check_generation(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: &Scope,
    request: &ReservationRequest,
    bootstrap: Option<&Digest>,
) -> Result<i64, StorageError> {
    let scoped = scope_values(scope);
    // FOR SHARE conflicts with activation's non-key UPDATE; FOR KEY SHARE
    // would leave a window in which stale policy could claim an effect.
    let row = transaction.query_opt(
        "SELECT w.active_generation_digest, (SELECT r.content_digest FROM workspace_revisions r WHERE r.institution_id = w.institution_id AND r.workspace_id = w.workspace_id AND r.revision = 0 AND r.record_kind = 'workspace_bootstrap'), w.revision FROM institution_workspaces w WHERE w.institution_id = $1 AND w.workspace_id = $2 AND w.trust_domain = $3 FOR SHARE OF w",
        &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
    ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
    let active: Option<String> = row.get(0);
    let expected = request.runtime_generation().digest().as_str();
    let matches = match bootstrap {
        None => active.as_deref() == Some(expected),
        Some(digest) => {
            let genesis: Option<String> = row.get(1);
            active.is_none()
                && genesis.as_deref() == Some(digest.as_str())
                && expected == digest.as_str()
        }
    };
    if !matches {
        return Err(StorageError::AttemptUnavailable);
    }
    Ok(row.get(2))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BudgetAmounts {
    wall_ms: u128,
    cpu_ms: u128,
    memory_bytes: u128,
    io_bytes: u128,
    network_bytes: u128,
    external_cost_microunits: u128,
}

impl BudgetAmounts {
    fn from_budget(budget: &ResourceBudget) -> Result<Self, StorageError> {
        Ok(Self {
            wall_ms: u128::from(budget.wall_ms.ok_or(StorageError::AttemptUnavailable)?),
            cpu_ms: u128::from(budget.cpu_ms.ok_or(StorageError::AttemptUnavailable)?),
            memory_bytes: u128::from(
                budget
                    .memory_bytes
                    .ok_or(StorageError::AttemptUnavailable)?,
            ),
            io_bytes: u128::from(budget.io_bytes.ok_or(StorageError::AttemptUnavailable)?),
            network_bytes: u128::from(
                budget
                    .network_bytes
                    .ok_or(StorageError::AttemptUnavailable)?,
            ),
            external_cost_microunits: u128::from(
                budget
                    .external_cost_microunits
                    .ok_or(StorageError::AttemptUnavailable)?,
            ),
        })
    }

    fn from_row(row: &tokio_postgres::Row, offset: usize) -> Result<Self, StorageError> {
        Ok(Self {
            wall_ms: parse_amount(&row.get::<_, String>(offset))?,
            cpu_ms: parse_amount(&row.get::<_, String>(offset + 1))?,
            memory_bytes: parse_amount(&row.get::<_, String>(offset + 2))?,
            io_bytes: parse_amount(&row.get::<_, String>(offset + 3))?,
            network_bytes: parse_amount(&row.get::<_, String>(offset + 4))?,
            external_cost_microunits: parse_amount(&row.get::<_, String>(offset + 5))?,
        })
    }

    fn as_strings(self) -> (String, String, String, String, String, String) {
        (
            self.wall_ms.to_string(),
            self.cpu_ms.to_string(),
            self.memory_bytes.to_string(),
            self.io_bytes.to_string(),
            self.network_bytes.to_string(),
            self.external_cost_microunits.to_string(),
        )
    }

    fn checked_add(self, other: Self) -> Result<Self, StorageError> {
        Ok(Self {
            wall_ms: self
                .wall_ms
                .checked_add(other.wall_ms)
                .ok_or(StorageError::AttemptUnavailable)?,
            cpu_ms: self
                .cpu_ms
                .checked_add(other.cpu_ms)
                .ok_or(StorageError::AttemptUnavailable)?,
            memory_bytes: self
                .memory_bytes
                .checked_add(other.memory_bytes)
                .ok_or(StorageError::AttemptUnavailable)?,
            io_bytes: self
                .io_bytes
                .checked_add(other.io_bytes)
                .ok_or(StorageError::AttemptUnavailable)?,
            network_bytes: self
                .network_bytes
                .checked_add(other.network_bytes)
                .ok_or(StorageError::AttemptUnavailable)?,
            external_cost_microunits: self
                .external_cost_microunits
                .checked_add(other.external_cost_microunits)
                .ok_or(StorageError::AttemptUnavailable)?,
        })
    }

    fn fits(self, limits: BudgetLimits, used: Self) -> bool {
        limits.wall_ms.is_none_or(|limit| {
            self.wall_ms
                .checked_add(used.wall_ms)
                .is_some_and(|total| total <= limit)
        }) && limits.cpu_ms.is_none_or(|limit| {
            self.cpu_ms
                .checked_add(used.cpu_ms)
                .is_some_and(|total| total <= limit)
        }) && limits.memory_bytes.is_none_or(|limit| {
            self.memory_bytes
                .checked_add(used.memory_bytes)
                .is_some_and(|total| total <= limit)
        }) && limits.io_bytes.is_none_or(|limit| {
            self.io_bytes
                .checked_add(used.io_bytes)
                .is_some_and(|total| total <= limit)
        }) && limits.network_bytes.is_none_or(|limit| {
            self.network_bytes
                .checked_add(used.network_bytes)
                .is_some_and(|total| total <= limit)
        }) && limits.external_cost_microunits.is_none_or(|limit| {
            self.external_cost_microunits
                .checked_add(used.external_cost_microunits)
                .is_some_and(|total| total <= limit)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BudgetLimits {
    wall_ms: Option<u128>,
    cpu_ms: Option<u128>,
    memory_bytes: Option<u128>,
    io_bytes: Option<u128>,
    network_bytes: Option<u128>,
    external_cost_microunits: Option<u128>,
}

impl BudgetLimits {
    fn from_budget(budget: &ResourceBudget) -> Self {
        Self {
            wall_ms: budget.wall_ms.map(u128::from),
            cpu_ms: budget.cpu_ms.map(u128::from),
            memory_bytes: budget.memory_bytes.map(u128::from),
            io_bytes: budget.io_bytes.map(u128::from),
            network_bytes: budget.network_bytes.map(u128::from),
            external_cost_microunits: budget.external_cost_microunits.map(u128::from),
        }
    }

    fn as_strings(self) -> BudgetLimitStrings {
        (
            self.wall_ms.map(|value| value.to_string()),
            self.cpu_ms.map(|value| value.to_string()),
            self.memory_bytes.map(|value| value.to_string()),
            self.io_bytes.map(|value| value.to_string()),
            self.network_bytes.map(|value| value.to_string()),
            self.external_cost_microunits.map(|value| value.to_string()),
        )
    }

    fn from_row(row: &tokio_postgres::Row, offset: usize) -> Result<Self, StorageError> {
        Ok(Self {
            wall_ms: row
                .get::<_, Option<String>>(offset)
                .map(|value| parse_amount(&value))
                .transpose()?,
            cpu_ms: row
                .get::<_, Option<String>>(offset + 1)
                .map(|value| parse_amount(&value))
                .transpose()?,
            memory_bytes: row
                .get::<_, Option<String>>(offset + 2)
                .map(|value| parse_amount(&value))
                .transpose()?,
            io_bytes: row
                .get::<_, Option<String>>(offset + 3)
                .map(|value| parse_amount(&value))
                .transpose()?,
            network_bytes: row
                .get::<_, Option<String>>(offset + 4)
                .map(|value| parse_amount(&value))
                .transpose()?,
            external_cost_microunits: row
                .get::<_, Option<String>>(offset + 5)
                .map(|value| parse_amount(&value))
                .transpose()?,
        })
    }
}

fn parse_amount(value: &str) -> Result<u128, StorageError> {
    value.parse().map_err(|_| StorageError::ImmutableConflict)
}

type BudgetLimitStrings = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn runtime_state_error(error: StorageError) -> RuntimeError {
    RuntimeError::AuthorizationState {
        source: Box::new(error),
    }
}

#[derive(Debug)]
struct ScopeValues {
    institution: Uuid,
    workspace: Uuid,
    trust_domain: String,
}

fn scope_values(scope: &Scope) -> ScopeValues {
    ScopeValues {
        institution: scope.institution.0,
        workspace: scope.workspace.0,
        trust_domain: scope.trust_domain.as_str().to_owned(),
    }
}

fn parse_digest(value: &str) -> Result<Digest, StorageError> {
    value.parse().map_err(|_| StorageError::ImmutableConflict)
}

fn is_serialization_failure(error: &tokio_postgres::Error) -> bool {
    error.code().is_some_and(|code| code.code() == "40001")
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "fixtures fail loudly when their PostgreSQL prerequisites are absent or invalid"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "fixtures consume JSON literals to keep construction local"
)]
mod tests {
    use super::*;

    fn test_scope() -> Scope {
        Scope::new(
            InstitutionId::new(),
            InstitutionWorkspaceId::new(),
            "storage-test:client"
                .parse()
                .expect("fixture trust domain is canonical"),
        )
    }

    fn signed(signer: &PrincipalId, value: Value) -> SignedRecord {
        SignedRecord::from_json(&value, signer.clone(), vec![1, 2, 3])
            .expect("fixture JSON is canonicalizable")
    }

    #[tokio::test]
    #[ignore = "requires POLITEIA_STORAGE_TEST_DATABASE_URL for a disposable PostgreSQL instance"]
    async fn postgres_commits_scoped_state_and_preserves_claimed_ambiguity() {
        let database_url = std::env::var("POLITEIA_STORAGE_TEST_DATABASE_URL")
            .expect("test database URL must be configured");
        let storage = PostgresStorage::connect(&database_url)
            .await
            .expect("test PostgreSQL is reachable");
        storage.migrate().await.expect("schema migrates");

        let scope = test_scope();
        let owner = PrincipalId::new();
        let owner_delegation = DelegationId::new();
        storage
            .bootstrap_workspace(&WorkspaceBootstrap {
                scope: scope.clone(),
                owner: owner.clone(),
                owner_delegation,
                model: signed(&owner, serde_json::json!({"model": "initial"})),
            })
            .await
            .expect("workspace bootstraps");

        let receipt = storage
            .commit(&ScopedCommit {
                scope: scope.clone(),
                expected_revision: 0,
                model: signed(&owner, serde_json::json!({"model": "approved"})),
                model_kind: "approved_model".to_owned(),
                transition: signed(&owner, serde_json::json!({"transition": "approve"})),
                state: vec![StateMutation {
                    key: "institution.phase".to_owned(),
                    value: signed(&owner, serde_json::json!({"value": "operational"})),
                }],
                evidence: vec![EvidenceAdmission {
                    id: EvidenceId::new(),
                    record: signed(&owner, serde_json::json!({"evidence": "approval"})),
                }],
                outbox: vec![OutboxMessage {
                    id: Uuid::now_v7(),
                    topic: "workspace.approved".to_owned(),
                    payload: signed(&owner, serde_json::json!({"revision": 1})),
                }],
            })
            .await
            .expect("state, journal, evidence, and outbox commit together");
        assert_eq!(receipt.revision, 1);

        let stale = storage
            .commit(&ScopedCommit {
                scope: scope.clone(),
                expected_revision: 0,
                model: signed(&owner, serde_json::json!({"model": "stale"})),
                model_kind: "approved_model".to_owned(),
                transition: signed(&owner, serde_json::json!({"transition": "stale"})),
                state: vec![],
                evidence: vec![],
                outbox: vec![],
            })
            .await;
        assert!(matches!(stale, Err(StorageError::RevisionConflict)));

        let generation = RuntimeGeneration {
            scope: scope.clone(),
            generation_digest: Digest::blake3(b"generation"),
            input_digest: Digest::blake3(b"inputs"),
            artifact_digest: Digest::blake3(b"artifact"),
            manifest: signed(&owner, serde_json::json!({"generation": "one"})),
        };
        storage
            .admit_generation(&generation)
            .await
            .expect("generation admits");
        storage
            .activate_generation(&ActivationCommit {
                scope: scope.clone(),
                expected_revision: 1,
                expected_active: None,
                generation: generation.generation_digest.clone(),
                transition: signed(&owner, serde_json::json!({"transition": "activate"})),
                evidence: vec![],
                outbox: vec![],
            })
            .await
            .expect("generation activates atomically");
        assert_eq!(
            storage
                .load_active_generation(&scope)
                .await
                .expect("workspace remains scoped"),
            Some(generation.generation_digest.clone())
        );

        let reservation = AttemptReservation {
            scope: scope.clone(),
            reservation_id: BudgetReservationId::new(),
            replay_domain: "operational".to_owned(),
            replay_key: Digest::blake3(b"effect subject"),
            claims_digest: Digest::blake3(b"claims"),
            retain_replay: true,
            request_payload: b"canonical request".to_vec(),
            expires_at: "2030-01-01T00:00:00Z".to_owned(),
        };
        storage
            .reserve_attempt(&reservation)
            .await
            .expect("attempt reserves before an effect");
        storage
            .claim_attempt(
                &scope,
                &reservation.reservation_id,
                &reservation.claims_digest,
            )
            .await
            .expect("attempt claims once before port invocation");
        assert_eq!(
            storage
                .load_attempt(&scope, &reservation.reservation_id)
                .await
                .expect("claimed row survives a process crash"),
            Attempt {
                status: AttemptStatus::Claimed,
                receipt_digest: None,
            }
        );
        assert!(matches!(
            storage
                .claim_attempt(
                    &scope,
                    &reservation.reservation_id,
                    &reservation.claims_digest
                )
                .await,
            Err(StorageError::AttemptUnavailable)
        ));
        storage
            .record_completion(
                &scope,
                &reservation.reservation_id,
                &Digest::blake3(b"receipt"),
            )
            .await
            .expect("only a post-effect receipt completes the attempt");
    }
}
