//! Immutable generation admission at the current authority boundary.

use politeia_core::{Delegation, trust::Admitted};
use tokio_postgres::{GenericClient, IsolationLevel};

use crate::{
    PostgresStorage, RuntimeGeneration, StorageError, authority, scope_values, transaction,
};

impl PostgresStorage {
    /// Persist a semantically admitted generation in the exact workspace scope.
    ///
    /// Callers that authorize through live delegations use
    /// `admit_generation_authorized` to fence that authority transactionally.
    pub async fn admit_generation(
        &self,
        generation: &RuntimeGeneration,
    ) -> Result<(), StorageError> {
        insert_generation(&self.client().await?, generation).await
    }

    /// Admit a generation only at the observed revision under its live grant chain.
    ///
    /// Artifact bytes may be staged before this call. They gain no durable
    /// generation authority if a competing revision or revocation wins first.
    pub async fn admit_generation_authorized(
        &self,
        generation: &RuntimeGeneration,
        expected_revision: i64,
        authority_chain: &[Admitted<Delegation>],
    ) -> Result<(), StorageError> {
        if authority_chain.is_empty() {
            return Err(StorageError::AdmissionMismatch);
        }
        transaction::retry(|| {
            self.admit_generation_once(generation, expected_revision, authority_chain)
        })
        .await
    }

    async fn admit_generation_once(
        &self,
        generation: &RuntimeGeneration,
        expected_revision: i64,
        authority_chain: &[Admitted<Delegation>],
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(&generation.scope);
        let row = transaction
            .query_opt(
                "SELECT revision FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 FOR UPDATE",
                &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::NotFound)?;
        if row.get::<_, i64>(0) != expected_revision {
            return Err(StorageError::RevisionConflict);
        }
        authority::check_authority_chain(&transaction, &generation.scope, authority_chain).await?;
        insert_generation(&transaction, generation).await?;
        transaction.commit().await.map_err(StorageError::Database)
    }
}

async fn insert_generation(
    client: &impl GenericClient,
    generation: &RuntimeGeneration,
) -> Result<(), StorageError> {
    let scoped = scope_values(&generation.scope);
    let inserted = client
        .execute(
            "INSERT INTO runtime_generations (institution_id, workspace_id, generation_digest, input_digest, artifact_digest, manifest, signature, signer_id) SELECT $1, $2, $3, $4, $5, $6, $7, $8 WHERE EXISTS (SELECT 1 FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $9) ON CONFLICT DO NOTHING",
            &[&scoped.institution, &scoped.workspace, &generation.generation_digest.as_str(), &generation.input_digest.as_str(), &generation.artifact_digest.as_str(), &generation.manifest.payload(), &generation.manifest.signature(), &generation.manifest.signer().0, &scoped.trust_domain],
        )
        .await
        .map_err(StorageError::Database)?;
    if inserted != 1 {
        return Err(StorageError::ImmutableConflict);
    }
    Ok(())
}
