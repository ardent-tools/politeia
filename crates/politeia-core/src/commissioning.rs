//! Validated commissioning authority, approvals, and generation-input provenance.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CommissioningRecordId, Delegation, DelegationId, Digest, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId,
    evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry},
    generation::ApprovedGenerationInputs,
    institution::InstitutionWorkspace,
};

mod grants;
mod record;
mod subjects;
#[cfg(test)]
mod tests;

pub use subjects::{
    commissioning_approval_subject_digest, commissioning_observation_set_digest,
    commissioning_observation_subject_digest, unresolved_obligations_digest,
};

/// Semantic action required by the first-proof commissioner grant.
pub const COMMISSION_ACTION: &str = "commission";

/// Canonical delegation resource for one institution workspace.
pub fn commissioning_workspace_resource(workspace: &InstitutionWorkspaceId) -> String {
    format!("institution-workspace:{}", workspace.0)
}

/// Canonical delegation audience for one institution.
pub fn commissioning_institution_audience(institution: &InstitutionId) -> String {
    format!("institution:{}", institution.0)
}

/// One persisted, workspace-scoped commissioner delegation offered to trusted bootstrap.
///
/// The record is inert input until [`TrustedCommissionerGrantRegistry`] admits
/// its identity and time interval. Its full delegation binds every authority,
/// resource, effect, data, audience, expiry, and budget axis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommissionerGrantRecord {
    /// Institution in which the grant applies.
    pub institution: InstitutionId,
    /// Exact client workspace covered by the grant.
    pub workspace: InstitutionWorkspaceId,
    /// Beginning of the trusted grant interval.
    pub valid_from: Timestamp,
    /// Trusted revocation time, when already revoked.
    pub revoked_at: Option<Timestamp>,
    /// Complete delegated authority.
    pub delegation: Delegation,
}

/// Immutable trusted snapshot of commissioner grants.
///
/// Construction is a host-authority action. The snapshot and its observation
/// time must come from the institution's trusted grant store, never from an
/// untrusted commissioning request.
#[derive(Clone, Debug)]
pub struct TrustedCommissionerGrantRegistry {
    as_of: Timestamp,
    grants: BTreeMap<DelegationId, CommissionerGrantRecord>,
}

/// A commissioner-grant snapshot was duplicated or temporally impossible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissionerGrantRegistryError {
    /// Two records used the same delegation identity.
    DuplicateIdentity,
    /// A grant began at/after expiry or had an impossible revocation time.
    InvalidInterval,
    /// Grant metadata and its exact commissioning resource/audience disagreed.
    ScopeMismatch,
}

/// Typed owner-approved subjects required to complete commissioning.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovedCommissioningSubject {
    /// Exact institution model selected for specialization.
    InstitutionalModel {
        /// Digest of the approved model.
        digest: Digest,
    },
    /// Exact policy identity and bytes.
    PolicyBundle {
        /// Policy bundle identity.
        id: PolicyBundleId,
        /// Digest of the approved policy bytes.
        digest: Digest,
    },
    /// Complete owner-approved specialization/build input set.
    GenerationInputs {
        /// Digest of [`ApprovedGenerationInputs`].
        digest: Digest,
    },
    /// Exact unresolved-obligation set, including an explicitly empty set.
    UnresolvedObligations {
        /// Domain-separated digest of the institution, workspace, and set.
        digest: Digest,
    },
}

/// One trusted institution-owner approval of an exact typed subject.
///
/// This output-only value is constructed by [`CommissioningRecord::new`] after
/// exact evidence resolution; raw wire input cannot instantiate it directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommissioningApproval {
    approved: ApprovedCommissioningSubject,
    evidence: EvidenceRecord,
}

/// Append-only provenance from bounded reconnaissance to approved generation inputs.
///
/// The record stores the complete admitted grant and evidence records, never
/// client payloads, secret values, or commissioner-controlled paths. It is
/// serializable for evidence storage but cannot be deserialized around the
/// trusted authority and evidence checks in [`Self::new`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommissioningRecord {
    id: CommissioningRecordId,
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    workspace_digest: Digest,
    captured_at: Timestamp,
    commissioner_grant: CommissionerGrantRecord,
    commissioner_grant_digest: Digest,
    observations: Vec<EvidenceRecord>,
    observation_set_digest: Digest,
    approvals: Vec<CommissioningApproval>,
    policy_bundle: PolicyBundleId,
    policy_digest: Digest,
    approved_generation: ApprovedGenerationInputs,
    unresolved_obligations: BTreeSet<String>,
    unresolved_obligations_digest: Digest,
}

/// Commissioning provenance was untrusted, empty, ambiguous, or incomplete.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommissioningError {
    /// No active grant existed for this exact workspace.
    MissingActiveGrant,
    /// More than one active grant existed for this exact workspace.
    AmbiguousActiveGrant,
    /// The sole active delegation was not issued by the workspace owner to a distinct commissioner.
    GrantAuthorityMismatch,
    /// A requested evidence identity was absent from trusted admission.
    EvidenceNotAdmitted,
    /// Trusted evidence was bound to another typed subject.
    EvidenceSubjectMismatch,
    /// Evidence was produced by a principal other than the required actor.
    EvidenceProducerMismatch,
    /// Evidence was produced under a delegation other than the required grant.
    EvidenceDelegationMismatch,
    /// Owner approval evidence lacked human-authority admission.
    EvidenceClassMismatch,
    /// Evidence was outside the active grant/snapshot interval or predated its basis.
    EvidenceOutsideWindow,
    /// Reconnaissance produced no admitted observations.
    MissingObservations,
    /// An approval was duplicated or did not match any required typed subject.
    UnexpectedApproval,
    /// One or more required typed subjects lacked approval.
    MissingRequiredApproval,
    /// A typed commissioning subject could not be encoded.
    Encoding(serde_json::Error),
}
