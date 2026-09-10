//! Atomic revocation of admitted authority with the owner's decision record.

use politeia_core::{DelegationId, Digest};
use tokio_postgres::IsolationLevel;

use crate::{CommitReceipt, EvidenceAdmission, PostgresStorage, Scope, StorageError, scope_values};

impl PostgresStorage {
    /// Revoke one exact delegation and append its authenticated decision atomically.
    ///
    /// The semantic service must admit the owner signature before calling this
    /// method. The workspace lock serializes the transition with reservation,
    /// claim, and activation; no effect can be claimed from a stale snapshot.
    pub async fn revoke_with_record(
        &self,
        scope: &Scope,
        delegation: &DelegationId,
        expected_delegation: &Digest,
        evidence: &EvidenceAdmission,
    ) -> Result<CommitReceipt, StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let workspace = transaction.query_opt(
            "SELECT revision FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 FOR UPDATE",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        let revision = workspace
            .get::<_, i64>(0)
            .checked_add(1)
            .ok_or(StorageError::RevisionConflict)?;
        let row = transaction.query_opt(
            "SELECT delegation_digest FROM delegations WHERE institution_id = $1 AND workspace_id = $2 AND delegation_id = $3 FOR UPDATE",
            &[&scoped.institution, &scoped.workspace, &delegation.0],
        ).await.map_err(StorageError::Database)?.ok_or(StorageError::NotFound)?;
        if row.get::<_, String>(0) != expected_delegation.as_str() {
            return Err(StorageError::AdmissionMismatch);
        }
        let record = &evidence.record;
        let inserted = transaction.execute(
            "INSERT INTO delegation_revocations (institution_id, workspace_id, delegation_id, revocation_digest, evidence_record_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &delegation.0, &record.digest().as_str(), &evidence.id.0],
        ).await.map_err(StorageError::Database)?;
        if inserted != 1 {
            return Err(StorageError::ImmutableConflict);
        }
        transaction.execute(
            "INSERT INTO evidence_journal (institution_id, workspace_id, evidence_id, evidence_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&scoped.institution, &scoped.workspace, &evidence.id.0, &record.digest().as_str(), &record.payload(), &record.signature(), &record.signer().0],
        ).await.map_err(StorageError::Database)?;
        let previous = transaction.query_opt(
            "SELECT transition_digest FROM transition_journal WHERE institution_id = $1 AND workspace_id = $2 ORDER BY sequence DESC LIMIT 1",
            &[&scoped.institution, &scoped.workspace],
        ).await.map_err(StorageError::Database)?.map(|row| row.get::<_, String>(0));
        transaction.execute(
            "INSERT INTO transition_journal (institution_id, workspace_id, transition_digest, previous_digest, payload) VALUES ($1, $2, $3, $4, $5)",
            &[&scoped.institution, &scoped.workspace, &record.digest().as_str(), &previous, &record.payload()],
        ).await.map_err(StorageError::Database)?;
        transaction.execute(
            "UPDATE institution_workspaces SET revision = $4, updated_at = CURRENT_TIMESTAMP WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain, &revision],
        ).await.map_err(StorageError::Database)?;
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(CommitReceipt {
            revision,
            transition_digest: record.digest().clone(),
        })
    }
}
