//! Recheck the host-admitted authority at the durable write boundary.

use std::collections::BTreeSet;

use politeia_core::{
    Delegation, Digest, PrincipalId,
    canonical::to_canonical_bytes,
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use tokio_postgres::Transaction;

use crate::{Scope, StorageError, scope_values};

/// The caller already holds the workspace update lock. Revocation takes that
/// same lock before changing authority, so both transitions have one order.
pub(super) async fn check_authority_chain(
    transaction: &Transaction<'_>,
    scope: &Scope,
    chain: &[Admitted<Delegation>],
) -> Result<(), StorageError> {
    let scoped = scope_values(scope);
    let owner = transaction
        .query_opt(
            "SELECT owner_principal_id FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 AND trust_domain = $3",
            &[&scoped.institution, &scoped.workspace, &scoped.trust_domain],
        )
        .await
        .map_err(StorageError::Database)?
        .ok_or(StorageError::NotFound)?;
    let owner = PrincipalId(owner.get(0));
    let mut previous: Option<&Delegation> = None;
    let mut seen = BTreeSet::new();
    for admitted in chain {
        let grant = admitted.payload();
        if admitted.kind() != AdmissionKind::Delegation
            || admitted.institution() != scope.institution()
            || admitted.workspace() != scope.workspace()
            || admitted.signer() != &grant.issuer
            || !seen.insert(&grant.id)
        {
            return Err(StorageError::AdmissionMismatch);
        }
        match previous {
            None if grant.parent.is_none() && grant.issuer == owner => {}
            Some(parent)
                if grant.parent.as_ref() == Some(&parent.id)
                    && grant.issuer == parent.subject
                    && grant.is_attenuation_of(parent) => {}
            _ => return Err(StorageError::AdmissionMismatch),
        }
        let expires_at = grant.expires_at.to_string();
        let row = transaction
            .query_opt(
                "SELECT d.delegation_digest, d.wire_digest, d.payload, d.signer_id, ($4::text::timestamptz > clock_timestamp()) FROM delegations d WHERE d.institution_id = $1 AND d.workspace_id = $2 AND d.delegation_id = $3 AND NOT EXISTS (SELECT 1 FROM delegation_revocations r WHERE r.institution_id = d.institution_id AND r.workspace_id = d.workspace_id AND r.delegation_id = d.delegation_id) FOR SHARE OF d",
                &[&scoped.institution, &scoped.workspace, &grant.id.0, &expires_at],
            )
            .await
            .map_err(StorageError::Database)?
            .ok_or(StorageError::AdmissionMismatch)?;
        let payload = to_canonical_bytes(grant).map_err(StorageError::Canonical)?;
        let wire_bytes: Vec<u8> = row.get(2);
        let wire: SignedAdmissionWire<Delegation> =
            serde_json::from_slice(&wire_bytes).map_err(|_| StorageError::AdmissionMismatch)?;
        if row.get::<_, String>(0) != Digest::blake3(&payload).as_str()
            || row.get::<_, String>(1) != Digest::blake3(&wire_bytes).as_str()
            || row.get::<_, uuid::Uuid>(3) != admitted.signer().0
            || wire.kind != AdmissionKind::Delegation
            || wire.institution != *scope.institution()
            || wire.workspace != *scope.workspace()
            || wire.signer != *admitted.signer()
            || wire.payload != *grant
            || !row.get::<_, bool>(4)
        {
            return Err(StorageError::AdmissionMismatch);
        }
        previous = Some(grant);
    }
    Ok(())
}
