//! Atomic completion evidence for protected operation attempts.

use std::collections::BTreeSet;

use politeia_core::{BudgetReservationId, Digest, canonical::to_canonical_bytes};
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::{PostgresStorage, Scope, StorageError, scope_values, transaction};

/// Immutable canonical JSON bytes and their derived content identity.
///
/// This record is deliberately unsigned. A service without a signing key may
/// preserve what it observed, while later verification and attestation remain
/// separate authority-bearing records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPayload {
    bytes: Vec<u8>,
    digest: Digest,
}

impl CanonicalPayload {
    /// Canonicalize one typed value and derive its content identity.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Canonical`] when JSON conversion or canonical
    /// encoding fails.
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, StorageError> {
        let value = serde_json::to_value(value).map_err(|error| {
            StorageError::Canonical(politeia_core::canonical::CanonicalError::Encoding(error))
        })?;
        Self::from_json(&value)
    }

    /// Canonicalize one JSON value and derive its content identity.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Canonical`] when canonical encoding fails.
    pub fn from_json(value: &Value) -> Result<Self, StorageError> {
        let bytes = to_canonical_bytes(value).map_err(StorageError::Canonical)?;
        let digest = Digest::blake3(&bytes);
        Ok(Self { bytes, digest })
    }

    /// Return the immutable canonical JSON bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the digest derived from the exact canonical bytes.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// One unsigned canonical outbox message committed with operation completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationOutboxMessage {
    /// Stable message identity supplied by the semantic service.
    pub id: Uuid,
    /// Declared destination/topic class.
    pub topic: String,
    /// Canonical immutable delivery document.
    pub payload: CanonicalPayload,
}

impl PostgresStorage {
    /// Atomically complete a claimed attempt, preserve its exact receipt bytes,
    /// and enqueue all corresponding operation messages.
    ///
    /// No completion or message becomes visible if any part of the transaction
    /// fails. The operation must already be `claimed`; a missing, reserved, or
    /// completed attempt is refused rather than rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::AttemptUnavailable`] for an invalid completion
    /// transition or malformed message topic, and a storage error for a
    /// conflicting outbox identity or failed database transaction.
    pub async fn record_completion_with_outbox(
        &self,
        scope: &Scope,
        reservation: &BudgetReservationId,
        receipt: &CanonicalPayload,
        outbox: &[OperationOutboxMessage],
    ) -> Result<(), StorageError> {
        let mut ids = BTreeSet::new();
        if outbox
            .iter()
            .any(|message| message.topic.trim().is_empty() || !ids.insert(message.id))
        {
            return Err(StorageError::AttemptUnavailable);
        }
        transaction::retry(|| self.record_completion_once(scope, reservation, receipt, outbox))
            .await
    }

    async fn record_completion_once(
        &self,
        scope: &Scope,
        reservation: &BudgetReservationId,
        receipt: &CanonicalPayload,
        outbox: &[OperationOutboxMessage],
    ) -> Result<(), StorageError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(scope);
        let completed = transaction
            .execute(
                "UPDATE operation_attempts a SET status = 'completed', receipt_digest = $4, receipt_payload = $5, completed_at = CURRENT_TIMESTAMP FROM institution_workspaces w WHERE a.institution_id = $1 AND a.workspace_id = $2 AND a.reservation_id = $3 AND a.status = 'claimed' AND w.institution_id = a.institution_id AND w.workspace_id = a.workspace_id AND w.trust_domain = $6",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &reservation.0,
                    &receipt.digest().as_str(),
                    &receipt.bytes(),
                    &scoped.trust_domain,
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        if completed != 1 {
            return Err(StorageError::AttemptUnavailable);
        }
        for message in outbox {
            transaction
                .execute(
                    "INSERT INTO transactional_outbox (institution_id, workspace_id, outbox_id, topic, payload, payload_digest) VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &scoped.institution,
                        &scoped.workspace,
                        &message.id,
                        &message.topic,
                        &message.payload.bytes(),
                        &message.payload.digest().as_str(),
                    ],
                )
                .await
                .map_err(StorageError::Database)?;
        }
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::CanonicalPayload;

    #[derive(Serialize)]
    struct Receipt<'a> {
        result: &'a str,
        count: u64,
    }

    #[test]
    fn canonical_payload_binds_sorted_exact_bytes() -> Result<(), crate::StorageError> {
        let payload = CanonicalPayload::from_serializable(&Receipt {
            result: "completed",
            count: 2,
        })?;
        assert_eq!(payload.bytes(), br#"{"count":2,"result":"completed"}"#);
        assert_eq!(
            payload.digest(),
            &politeia_core::Digest::blake3(payload.bytes())
        );
        Ok(())
    }
}
