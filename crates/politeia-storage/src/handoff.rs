//! Atomic persistence of an evidence-backed operational handoff.

use std::collections::BTreeSet;

use jiff::Timestamp;
use politeia_core::{
    Delegation, DelegationId, Digest,
    canonical::to_canonical_bytes,
    commissioning::{
        COMMISSION_ACTION, commissioning_institution_audience, commissioning_workspace_resource,
    },
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use tokio_postgres::IsolationLevel;

use crate::{
    HandoffCommit, HandoffCommitReceipt, PostgresStorage, StorageError, StoredHandoffReceipt,
    advance_workspace_admission_epoch, authority, parse_digest, scope_values, transaction,
};

const HANDOFF_RECORD_KIND: &str = "handoff_receipt";

impl PostgresStorage {
    /// Atomically retain a daemon-derived handoff receipt and its owner evidence.
    ///
    /// The transaction first advances the shared admission epoch, then
    /// serializes on the workspace, verifies the active generation and
    /// revision, rechecks the live installed-owner root grant, compares the
    /// complete relevant commissioner-authority set, and resolves the exact
    /// completed operation receipt. A concurrent commissioner grant therefore
    /// either follows this handoff or becomes visible before validation; it
    /// cannot disappear from the handoff record.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::RevisionConflict`] when generation, revision, or
    /// a closed authority-membership snapshot changed; [`StorageError::AdmissionMismatch`]
    /// when signed owner authority or live commissioner closure is invalid; and
    /// [`StorageError::AttemptUnavailable`] when the selected continuity receipt
    /// is missing, incomplete, mismatched, was reserved before authority
    /// closure, or completed before authority closure.
    pub async fn commit_handoff_authorized(
        &self,
        handoff: &HandoffCommit,
        owner_authority: &[Admitted<Delegation>],
    ) -> Result<HandoffCommitReceipt, StorageError> {
        validate_shape(handoff, owner_authority)?;
        transaction::retry(|| self.commit_handoff_once(handoff, owner_authority)).await
    }

    async fn commit_handoff_once(
        &self,
        handoff: &HandoffCommit,
        owner_authority: &[Admitted<Delegation>],
    ) -> Result<HandoffCommitReceipt, StorageError> {
        let commit = &handoff.transition;
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(StorageError::Database)?;
        let scoped = scope_values(&commit.scope);
        advance_workspace_admission_epoch(&transaction, &commit.scope).await?;
        let workspace = transaction
            .query_opt(
                "SELECT revision, active_generation_digest, owner_principal_id, owner_delegation_id, model_digest, model_payload, model_signature, model_signer_id, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000000)::bigint FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 FOR UPDATE",
                &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::NotFound)?;
        let revision: i64 = workspace.get(0);
        let active: Option<String> = workspace.get(1);
        if revision != commit.expected_revision
            || active.as_deref() != Some(handoff.generation.as_str())
        {
            return Err(StorageError::RevisionConflict);
        }
        let owner = politeia_core::PrincipalId(workspace.get(2));
        let owner_delegation = DelegationId(workspace.get(3));
        let owner_grant = owner_authority
            .first()
            .ok_or(StorageError::AdmissionMismatch)?;
        if owner_authority.len() != 1
            || owner_grant.payload().id != owner_delegation
            || owner_grant.payload().issuer != owner
            || owner_grant.payload().subject != owner
            || owner_grant.payload().parent.is_some()
        {
            return Err(StorageError::AdmissionMismatch);
        }
        if workspace.get::<_, String>(4) != commit.model.digest().as_str()
            || workspace.get::<_, Vec<u8>>(5) != commit.model.payload()
            || workspace.get::<_, Vec<u8>>(6) != commit.model.signature()
            || workspace.get::<_, uuid::Uuid>(7) != commit.model.signer().0
        {
            return Err(StorageError::RevisionConflict);
        }
        authority::check_authority_chain(&transaction, &commit.scope, owner_authority).await?;
        let observed_at = timestamp_from_micros(workspace.get(8))?;

        let mut actual_authorities = BTreeSet::new();
        let mut latest_authority_end = None;
        for row in transaction
            .query(
                "SELECT d.delegation_id, d.delegation_digest, d.wire_digest, d.payload, d.signer_id, d.signature, (EXTRACT(EPOCH FROM r.revoked_at) * 1000000)::bigint FROM delegations d LEFT JOIN delegation_revocations r USING (institution_id, workspace_id, delegation_id) WHERE d.institution_id = $1 AND d.workspace_id = $2 ORDER BY d.delegation_id FOR SHARE OF d",
                &[&scoped.institution, &scoped.workspace],
            )
            .await
            .map_err(StorageError::Database)?
        {
            let id = DelegationId(row.get(0));
            let wire_bytes: Vec<u8> = row.get(3);
            let wire: SignedAdmissionWire<Delegation> =
                serde_json::from_slice(&wire_bytes).map_err(|_| StorageError::AdmissionMismatch)?;
            let semantic = to_canonical_bytes(&wire.payload).map_err(StorageError::Canonical)?;
            if wire.kind != AdmissionKind::Delegation
                || wire.institution != *commit.scope.institution()
                || wire.workspace != *commit.scope.workspace()
                || wire.payload.id != id
                || wire.signer.0 != row.get::<_, uuid::Uuid>(4)
                || wire.signature != row.get::<_, Vec<u8>>(5)
                || row.get::<_, String>(1) != Digest::blake3(&semantic).as_str()
                || row.get::<_, String>(2) != Digest::blake3(&wire_bytes).as_str()
            {
                return Err(StorageError::AdmissionMismatch);
            }
            let is_original_commissioner = wire.payload.subject == handoff.commissioner;
            let is_commissioner_grant = is_scoped_commissioner_grant(
                &wire.payload,
                &owner,
                commit.scope.institution(),
                commit.scope.workspace(),
            );
            if !is_original_commissioner && !is_commissioner_grant {
                continue;
            }
            actual_authorities.insert(id);
            let revoked_at = row
                .get::<_, Option<i64>>(6)
                .map(timestamp_from_micros)
                .transpose()?;
            let authority_end = revoked_at
                .map_or(wire.payload.expires_at, |revoked| revoked.min(wire.payload.expires_at));
            if authority_end > observed_at {
                return Err(StorageError::AdmissionMismatch);
            }
            latest_authority_end = Some(
                latest_authority_end.map_or(authority_end, |latest: Timestamp| {
                    latest.max(authority_end)
                }),
            );
        }
        if actual_authorities != handoff.expected_authorities {
            return Err(StorageError::RevisionConflict);
        }
        let latest_authority_end = latest_authority_end.ok_or(StorageError::AdmissionMismatch)?;

        let attempt = transaction
            .query_opt(
                "SELECT a.status::text, a.receipt_digest, a.receipt_payload, (EXTRACT(EPOCH FROM a.completed_at) * 1000000)::bigint, a.retain_replay, (EXTRACT(EPOCH FROM a.created_at) * 1000000)::bigint FROM operation_attempts a JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE a.institution_id = $1 AND a.workspace_id = $2 AND a.reservation_id = $3 AND w.trust_domain = $4 FOR SHARE OF a",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &handoff.continuity_reservation.0,
                    &scoped.trust_domain,
                ],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::AttemptUnavailable)?;
        let receipt_digest: Option<String> = attempt.get(1);
        let receipt_payload: Option<Vec<u8>> = attempt.get(2);
        let completed_at: Option<i64> = attempt.get(3);
        let created_at = timestamp_from_micros(attempt.get(5))?;
        if attempt.get::<_, String>(0) != "completed"
            || !attempt.get::<_, bool>(4)
            || receipt_digest.as_deref() != Some(handoff.continuity_receipt.digest().as_str())
            || receipt_payload.as_deref() != Some(handoff.continuity_receipt.bytes())
            || created_at <= latest_authority_end
            || completed_at
                .map(timestamp_from_micros)
                .transpose()?
                .is_none_or(|completed| completed <= latest_authority_end)
        {
            return Err(StorageError::AttemptUnavailable);
        }

        let next_revision = revision
            .checked_add(1)
            .ok_or(StorageError::RevisionConflict)?;
        let updated = transaction
            .execute(
                "UPDATE institution_workspaces SET revision = $4, updated_at = CURRENT_TIMESTAMP WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3 AND revision = $5 AND active_generation_digest = $6",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &scoped.trust_domain,
                    &next_revision,
                    &revision,
                    &handoff.generation.as_str(),
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        if updated != 1 {
            return Err(StorageError::RevisionConflict);
        }
        transaction
            .execute(
                "INSERT INTO workspace_revisions (institution_id, workspace_id, revision, record_kind, content_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &next_revision,
                    &commit.model_kind,
                    &commit.model.digest().as_str(),
                    &commit.model.payload(),
                    &commit.model.signature(),
                    &commit.model.signer().0,
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        let previous = transaction
            .query_opt(
                "SELECT transition_digest FROM transition_journal WHERE institution_id = $1 AND workspace_id = $2 ORDER BY sequence DESC LIMIT 1 FOR KEY SHARE",
                &[&scoped.institution, &scoped.workspace],
            )
            .await
            .map_err(StorageError::Database)?
            .map(|row| row.get::<_, String>(0));
        transaction
            .execute(
                "INSERT INTO transition_journal (institution_id, workspace_id, transition_digest, previous_digest, payload) VALUES ($1, $2, $3, $4, $5)",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &commit.transition.digest().as_str(),
                    &previous,
                    &commit.transition.payload(),
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        for evidence in &commit.evidence {
            transaction
                .execute(
                    "INSERT INTO evidence_journal (institution_id, workspace_id, evidence_id, evidence_digest, payload, signature, signer_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    &[
                        &scoped.institution,
                        &scoped.workspace,
                        &evidence.id.0,
                        &evidence.record.digest().as_str(),
                        &evidence.record.payload(),
                        &evidence.record.signature(),
                        &evidence.record.signer().0,
                    ],
                )
                .await
                .map_err(StorageError::Database)?;
        }
        let accepted = transaction
            .query_one(
                "INSERT INTO handoff_receipts (institution_id, workspace_id, generation_digest, commissioning_record_id, continuity_reservation_id, continuity_receipt_digest, handoff_receipt_digest, payload, transition_digest, workspace_revision) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING (EXTRACT(EPOCH FROM accepted_at) * 1000000)::bigint",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &handoff.generation.as_str(),
                    &handoff.commissioning_record.0,
                    &handoff.continuity_reservation.0,
                    &handoff.continuity_receipt.digest().as_str(),
                    &handoff.handoff_receipt.digest().as_str(),
                    &handoff.handoff_receipt.bytes(),
                    &commit.transition.digest().as_str(),
                    &next_revision,
                ],
            )
            .await
            .map_err(StorageError::Database)?;
        let accepted_at = timestamp_from_micros(accepted.get(0))?;
        transaction.commit().await.map_err(StorageError::Database)?;
        Ok(HandoffCommitReceipt {
            revision: next_revision,
            transition_digest: commit.transition.digest().clone(),
            handoff_receipt_digest: handoff.handoff_receipt.digest().clone(),
            accepted_at,
        })
    }

    /// Load exact immutable handoff receipt bytes for one generation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] when no receipt exists in the exact
    /// scope and rejects any stored digest mismatch before returning bytes.
    pub async fn load_handoff_receipt(
        &self,
        scope: &crate::Scope,
        generation: &Digest,
    ) -> Result<StoredHandoffReceipt, StorageError> {
        let client = self.client().await?;
        let scoped = scope_values(scope);
        let row = client
            .query_opt(
                "SELECT h.commissioning_record_id, h.continuity_reservation_id, h.continuity_receipt_digest, h.handoff_receipt_digest, h.payload, h.transition_digest, h.workspace_revision, (EXTRACT(EPOCH FROM h.accepted_at) * 1000000)::bigint FROM handoff_receipts h JOIN institution_workspaces w USING (institution_id, workspace_id) WHERE h.institution_id = $1 AND h.workspace_id = $2 AND h.generation_digest = $3 AND w.trust_domain = $4",
                &[
                    &scoped.institution,
                    &scoped.workspace,
                    &generation.as_str(),
                    &scoped.trust_domain,
                ],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::NotFound)?;
        let handoff_receipt_digest = parse_digest(&row.get::<_, String>(3))?;
        let payload: Vec<u8> = row.get(4);
        let actual = Digest::blake3(&payload);
        if actual != handoff_receipt_digest {
            return Err(StorageError::DigestMismatch {
                expected: handoff_receipt_digest,
                actual,
            });
        }
        Ok(StoredHandoffReceipt {
            generation: generation.clone(),
            commissioning_record: politeia_core::CommissioningRecordId(row.get(0)),
            continuity_reservation: politeia_core::BudgetReservationId(row.get(1)),
            continuity_receipt_digest: parse_digest(&row.get::<_, String>(2))?,
            handoff_receipt_digest: Digest::blake3(&payload),
            payload,
            transition_digest: parse_digest(&row.get::<_, String>(5))?,
            revision: row.get(6),
            accepted_at: timestamp_from_micros(row.get(7))?,
        })
    }
}

fn validate_shape(
    handoff: &HandoffCommit,
    owner_authority: &[Admitted<Delegation>],
) -> Result<(), StorageError> {
    let commit = &handoff.transition;
    let evidence_ids: BTreeSet<_> = commit
        .evidence
        .iter()
        .map(|evidence| &evidence.id)
        .collect();
    if commit.model_kind != HANDOFF_RECORD_KIND
        || !commit.state.is_empty()
        || !commit.outbox.is_empty()
        || commit.evidence.len() != 2
        || evidence_ids.len() != 2
        || !commit
            .evidence
            .iter()
            .any(|evidence| evidence.record.digest() == commit.transition.digest())
        || handoff.expected_authorities.is_empty()
        || owner_authority.len() != 1
    {
        return Err(StorageError::AdmissionMismatch);
    }
    Ok(())
}

fn is_scoped_commissioner_grant(
    delegation: &Delegation,
    owner: &politeia_core::PrincipalId,
    institution: &politeia_core::InstitutionId,
    workspace: &politeia_core::InstitutionWorkspaceId,
) -> bool {
    if delegation.subject == *owner || !delegation.actions.contains(COMMISSION_ACTION) {
        return false;
    }
    let expected_workspace = commissioning_workspace_resource(workspace);
    let workspace_scopes: Vec<_> = delegation
        .resources
        .iter()
        .filter(|resource| resource.starts_with("institution-workspace:"))
        .collect();
    let expected_institution = commissioning_institution_audience(institution);
    let institution_scopes: Vec<_> = delegation
        .audience
        .iter()
        .filter(|audience| audience.starts_with("institution:"))
        .collect();
    workspace_scopes == [&expected_workspace] && institution_scopes == [&expected_institution]
}

fn timestamp_from_micros(micros: i64) -> Result<Timestamp, StorageError> {
    let nanos = i32::try_from(micros.rem_euclid(1_000_000) * 1_000)
        .map_err(|_| StorageError::AdmissionMismatch)?;
    Timestamp::new(micros.div_euclid(1_000_000), nanos).map_err(|_| StorageError::AdmissionMismatch)
}
