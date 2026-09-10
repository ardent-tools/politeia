//! Coherent, inert recovery snapshots from scoped PostgreSQL state.

use std::collections::BTreeMap;

use jiff::Timestamp;
use politeia_core::{
    Delegation, DelegationId, Digest, EvidenceId, PrincipalId, trust::SignedAdmissionWire,
};
use tokio_postgres::{IsolationLevel, Row};

use crate::{PostgresStorage, Scope, SignedRecord, StorageError, parse_digest, scope_values};

/// An immutable byte reference; the semantic consumer must re-admit its content.
#[derive(Clone, Debug)]
pub struct StoredPayload {
    /// Exact preserved canonical bytes.
    pub bytes: Vec<u8>,
    /// Verified content hash of those bytes.
    pub digest: Digest,
}

impl StoredPayload {
    fn from_row(
        row: &Row,
        digest_column: usize,
        bytes_column: usize,
    ) -> Result<Self, StorageError> {
        let digest = parse_digest(&row.get::<_, String>(digest_column))?;
        let bytes: Vec<u8> = row.get(bytes_column);
        let actual = Digest::blake3(&bytes);
        if actual != digest {
            return Err(StorageError::DigestMismatch {
                expected: digest,
                actual,
            });
        }
        Ok(Self { bytes, digest })
    }
}

/// A stored delegation envelope with its durable revocation state.
///
/// The envelope remains untrusted until the service resolves installed anchors,
/// issuer/parent authority, exact scope, expiry, and this revocation state.
#[derive(Clone, Debug)]
pub struct PersistedDelegation {
    /// Inert signed delegation recovered without inventing a new identity.
    pub wire: SignedAdmissionWire<Delegation>,
    /// Whether an immutable revocation exists for this delegation.
    pub revoked: bool,
    /// Trusted instant at which the durable authority admitted this envelope.
    pub admitted_at: Timestamp,
}

/// One coherent recovery snapshot, read at a single PostgreSQL MVCC boundary.
///
/// None of these records are privileged semantic types. A transport may not
/// expose this complete private snapshot as ordinary status or task context.
#[derive(Clone, Debug)]
pub struct WorkspaceSnapshot {
    /// Exact scope checked against durable workspace ownership.
    pub scope: Scope,
    /// Revision used for the next atomic compare-and-swap.
    pub revision: i64,
    /// Installed owner identity to compare with host trust configuration.
    pub owner: PrincipalId,
    /// Owner delegation originally bound at initialization.
    pub owner_delegation: DelegationId,
    /// Preserved signed model or workspace envelope, awaiting re-admission.
    pub model: SignedRecord,
    /// Current generation pointer from the same snapshot.
    pub active_generation: Option<Digest>,
    /// Normalized current state projections, retaining their exact bytes.
    pub state: BTreeMap<String, StoredPayload>,
    /// Immutable signed evidence records, awaiting re-admission.
    pub evidence: BTreeMap<EvidenceId, SignedRecord>,
    /// Signed grants and their revocation state from the same snapshot.
    pub delegations: BTreeMap<DelegationId, PersistedDelegation>,
}

impl PostgresStorage {
    /// Return the immutable installation record independently of later models.
    ///
    /// A host must re-admit this signed wire against its installed anchors;
    /// this method validates storage integrity and the complete workspace scope.
    pub async fn load_bootstrap(&self, scope: &Scope) -> Result<SignedRecord, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let row = client.query_opt(
            "SELECT r.content_digest, r.payload, r.signer_id, r.signature FROM workspace_revisions r JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE r.institution_id = $1 AND r.workspace_id = $2 AND w.trust_domain = $3 AND r.revision = 0 AND r.record_kind = 'workspace_bootstrap'",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        signed_from_row(&row, 0, 1, 2, 3)
    }

    /// Recover current state and immutable provenance at one consistent revision.
    ///
    /// Every query checks all three scope axes through the workspace row. Hash
    /// or stored-envelope inconsistencies fail recovery before any interpretation.
    pub async fn load_workspace(&self, scope: &Scope) -> Result<WorkspaceSnapshot, StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let row = transaction.query_opt(
            "SELECT revision, owner_principal_id, owner_delegation_id, model_digest, model_payload, model_signer_id, model_signature, active_generation_digest FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        let model = signed_from_row(&row, 3, 4, 5, 6)?;
        let mut state = BTreeMap::new();
        for state_row in transaction.query(
            "SELECT state_key, value_digest, value_payload FROM state_entries WHERE institution_id = $1 AND workspace_id = $2 ORDER BY state_key",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)? {
            state.insert(state_row.get(0), StoredPayload::from_row(&state_row, 1, 2)?);
        }
        let mut evidence = BTreeMap::new();
        for evidence_row in transaction.query(
            "SELECT evidence_id, evidence_digest, payload, signer_id, signature FROM evidence_journal WHERE institution_id = $1 AND workspace_id = $2 ORDER BY evidence_id",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)? {
            evidence.insert(EvidenceId(evidence_row.get(0)), signed_from_row(&evidence_row, 1, 2, 3, 4)?);
        }
        let mut delegations = BTreeMap::new();
        for delegation_row in transaction.query(
            "SELECT d.delegation_id, d.delegation_digest, d.wire_digest, d.payload, d.signer_id, d.signature, r.delegation_id IS NOT NULL, (EXTRACT(EPOCH FROM d.admitted_at) * 1000000)::bigint FROM delegations d LEFT JOIN delegation_revocations r USING (institution_id, workspace_id, delegation_id) WHERE d.institution_id = $1 AND d.workspace_id = $2 ORDER BY d.delegation_id",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)? {
            let record = signed_from_row(&delegation_row, 2, 3, 4, 5)?;
            let wire: SignedAdmissionWire<Delegation> = serde_json::from_slice(record.payload())
                .map_err(|error| StorageError::Canonical(error.into()))?;
            let id = DelegationId(delegation_row.get(0));
            let semantic = Digest::blake3(&politeia_core::canonical::to_canonical_bytes(&wire.payload)
                .map_err(StorageError::Canonical)?);
            if wire.payload.id != id || wire.signer != *record.signer()
                || wire.signature != record.signature()
                || wire.institution != *scope.institution() || wire.workspace != *scope.workspace()
                || semantic.as_str() != delegation_row.get::<_, String>(1) {
                return Err(StorageError::AdmissionMismatch);
            }
            let micros: i64 = delegation_row.get(7);
            let admitted_at = Timestamp::new(
                micros.div_euclid(1_000_000),
                (micros.rem_euclid(1_000_000) * 1_000) as i32,
            )
                .map_err(|_| StorageError::AdmissionMismatch)?;
            delegations.insert(id, PersistedDelegation {
                wire,
                revoked: delegation_row.get(6),
                admitted_at,
            });
        }
        let snapshot = WorkspaceSnapshot {
            scope: scope.clone(),
            revision: row.get(0),
            owner: PrincipalId(row.get(1)),
            owner_delegation: DelegationId(row.get(2)),
            model,
            active_generation: row
                .get::<_, Option<String>>(7)
                .map(|value| parse_digest(&value))
                .transpose()?,
            state,
            evidence,
            delegations,
        };
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(snapshot)
    }

    /// Return one inert normalized state object after validating its complete scope.
    pub async fn load_state(
        &self,
        scope: &Scope,
        key: &str,
    ) -> Result<Option<StoredPayload>, StorageError> {
        Ok(self.load_workspace(scope).await?.state.remove(key))
    }

    /// Return an inert delegation and its durable revocation state.
    pub async fn load_delegation(
        &self,
        scope: &Scope,
        id: &DelegationId,
    ) -> Result<PersistedDelegation, StorageError> {
        self.load_workspace(scope)
            .await?
            .delegations
            .remove(id)
            .ok_or(StorageError::NotFound)
    }
}

fn signed_from_row(
    row: &Row,
    digest: usize,
    payload: usize,
    signer: usize,
    signature: usize,
) -> Result<SignedRecord, StorageError> {
    SignedRecord::from_bytes(
        row.get(payload),
        parse_digest(&row.get::<_, String>(digest))?,
        PrincipalId(row.get(signer)),
        row.get(signature),
    )
}
