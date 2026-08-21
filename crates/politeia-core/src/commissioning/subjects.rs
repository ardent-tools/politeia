//! Domain-separated commissioning evidence subjects and digests.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::{Digest, EvidenceId, InstitutionId, InstitutionWorkspaceId, evidence::EvidenceRecord};

use super::ApprovedCommissioningSubject;
use crate::canonical::{CanonicalError, to_canonical_bytes};

#[derive(Serialize)]
struct ObservationSubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    commissioner_grant_digest: &'a Digest,
    payload_digest: &'a Digest,
}

#[derive(Serialize)]
struct ApprovalSubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    approved: &'a ApprovedCommissioningSubject,
    observation_set_digest: &'a Digest,
}

#[derive(Serialize)]
struct ObservationSetSubject<'a> {
    kind: &'static str,
    records: &'a [(EvidenceId, Digest)],
}

#[derive(Serialize)]
struct UnresolvedObligationsSubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    obligations: &'a BTreeSet<String>,
}

/// Digest an observation subject under one exact commissioner grant.
///
/// # Errors
///
/// Returns the JSON encoding failure if the subject cannot be represented.
pub fn commissioning_observation_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    commissioner_grant_digest: &Digest,
    payload_digest: &Digest,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(&ObservationSubject {
        kind: "commissioning_observation_v1",
        institution,
        workspace,
        commissioner_grant_digest,
        payload_digest,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Digest one exact typed owner-approval subject and its observation basis.
///
/// # Errors
///
/// Returns the JSON encoding failure if the subject cannot be represented.
pub fn commissioning_approval_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    approved: &ApprovedCommissioningSubject,
    observation_set_digest: &Digest,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(&ApprovalSubject {
        kind: "commissioning_approval_v1",
        institution,
        workspace,
        approved,
        observation_set_digest,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Digest the exact unresolved-obligation set requiring owner approval.
///
/// The empty set remains an explicit subject: absence of known obligations
/// cannot replace an approved assertion that none remain.
///
/// # Errors
///
/// Returns the JSON encoding failure if the subject cannot be represented.
pub fn unresolved_obligations_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    obligations: &BTreeSet<String>,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(&UnresolvedObligationsSubject {
        kind: "commissioning_unresolved_obligations_v1",
        institution,
        workspace,
        obligations,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Digest the exact sorted set of admitted observation records.
///
/// # Errors
///
/// Returns the JSON encoding failure if any record or the set cannot be represented.
pub fn commissioning_observation_set_digest(
    records: &[EvidenceRecord],
) -> Result<Digest, CanonicalError> {
    let mut records = records
        .iter()
        .map(|record| record.digest().map(|digest| (record.id.clone(), digest)))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort();
    to_canonical_bytes(&ObservationSetSubject {
        kind: "commissioning_observation_set_v1",
        records: &records,
    })
    .map(|bytes| Digest::blake3(&bytes))
}
