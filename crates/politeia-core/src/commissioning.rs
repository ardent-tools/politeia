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

#[derive(Serialize)]
struct CommissionerGrantIdentity<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    valid_from: Timestamp,
    delegation: &'a Delegation,
}

impl CommissionerGrantRecord {
    /// Digest the immutable grant authority axes.
    ///
    /// Revocation state is deliberately excluded: the same admitted grant
    /// retains one identity when its trusted store later records revocation.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the record cannot be represented.
    pub fn digest(&self) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(&CommissionerGrantIdentity {
            kind: "commissioner_grant_v1",
            institution: &self.institution,
            workspace: &self.workspace,
            valid_from: self.valid_from,
            delegation: &self.delegation,
        })
        .map(|bytes| Digest::blake3(&bytes))
    }

    /// Earliest trusted instant at which this grant no longer carries authority.
    ///
    /// Expiry remains authoritative when it precedes a later recorded
    /// revocation; revocation cannot extend a delegation's lifetime.
    pub fn authority_ended_at(&self) -> Timestamp {
        self.revoked_at
            .map_or(self.delegation.expires_at, |revoked| {
                revoked.min(self.delegation.expires_at)
            })
    }
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

impl TrustedCommissionerGrantRegistry {
    /// Admit one trusted snapshot of commissioner grants.
    ///
    /// # Errors
    ///
    /// Returns [`CommissionerGrantRegistryError`] for duplicate delegation
    /// identities, impossible grant intervals, or future-dated revocations.
    ///
    /// Time: O(g log g). Space: O(g), where g is the grant count.
    pub fn from_trusted_bootstrap(
        as_of: Timestamp,
        grants: impl IntoIterator<Item = CommissionerGrantRecord>,
    ) -> Result<Self, CommissionerGrantRegistryError> {
        let mut registry = BTreeMap::new();
        for grant in grants {
            if grant.valid_from >= grant.delegation.expires_at
                || grant
                    .revoked_at
                    .is_some_and(|revoked| revoked < grant.valid_from || revoked > as_of)
            {
                return Err(CommissionerGrantRegistryError::InvalidInterval);
            }
            let expected_workspace = commissioning_workspace_resource(&grant.workspace);
            let workspace_scopes: Vec<_> = grant
                .delegation
                .resources
                .iter()
                .filter(|resource| resource.starts_with("institution-workspace:"))
                .collect();
            let expected_institution = commissioning_institution_audience(&grant.institution);
            let institution_scopes: Vec<_> = grant
                .delegation
                .audience
                .iter()
                .filter(|audience| audience.starts_with("institution:"))
                .collect();
            if !grant.delegation.actions.contains(COMMISSION_ACTION)
                || workspace_scopes != [&expected_workspace]
                || institution_scopes != [&expected_institution]
            {
                return Err(CommissionerGrantRegistryError::ScopeMismatch);
            }
            if registry
                .insert(grant.delegation.id.clone(), grant)
                .is_some()
            {
                return Err(CommissionerGrantRegistryError::DuplicateIdentity);
            }
        }
        Ok(Self {
            as_of,
            grants: registry,
        })
    }

    fn active_for<'a>(
        &'a self,
        institution: &'a InstitutionId,
        workspace: &'a InstitutionWorkspaceId,
    ) -> impl Iterator<Item = &'a CommissionerGrantRecord> + 'a {
        self.grants.values().filter(move |grant| {
            &grant.institution == institution
                && &grant.workspace == workspace
                && grant.valid_from <= self.as_of
                && self.as_of < grant.delegation.expires_at
                && grant
                    .revoked_at
                    .is_none_or(|revoked_at| self.as_of < revoked_at)
        })
    }

    /// Resolve one exact grant record by delegation identity.
    pub fn resolve(&self, id: &DelegationId) -> Option<&CommissionerGrantRecord> {
        self.grants.get(id)
    }

    /// Count grants still active for one exact workspace at this snapshot.
    pub fn active_count_for(
        &self,
        institution: &InstitutionId,
        workspace: &InstitutionWorkspaceId,
    ) -> usize {
        self.active_for(institution, workspace).count()
    }

    /// Latest authority end among every admitted grant for one workspace.
    ///
    /// This includes grants that ended before the snapshot and grants scheduled
    /// to begin later. A handoff continuity proof must postdate this value so a
    /// grant cannot disappear merely because it ended between observation and
    /// snapshot time.
    pub fn latest_authority_end_for(
        &self,
        institution: &InstitutionId,
        workspace: &InstitutionWorkspaceId,
    ) -> Option<Timestamp> {
        self.grants
            .values()
            .filter(|grant| &grant.institution == institution && &grant.workspace == workspace)
            .map(CommissionerGrantRecord::authority_ended_at)
            .max()
    }

    /// Trusted time represented by this immutable grant snapshot.
    pub fn as_of(&self) -> Timestamp {
        self.as_of
    }
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

impl std::fmt::Display for CommissionerGrantRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateIdentity => formatter.write_str("duplicate commissioner-grant identity"),
            Self::InvalidInterval => {
                formatter.write_str("commissioner grant has an invalid trusted interval")
            }
            Self::ScopeMismatch => {
                formatter.write_str("commissioner grant metadata contradicts its workspace scope")
            }
        }
    }
}

impl std::error::Error for CommissionerGrantRegistryError {}

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
) -> Result<Digest, serde_json::Error> {
    serde_json::to_vec(&ObservationSubject {
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
) -> Result<Digest, serde_json::Error> {
    serde_json::to_vec(&ApprovalSubject {
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
) -> Result<Digest, serde_json::Error> {
    serde_json::to_vec(&UnresolvedObligationsSubject {
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
) -> Result<Digest, serde_json::Error> {
    let mut records = records
        .iter()
        .map(|record| record.digest().map(|digest| (record.id.clone(), digest)))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort();
    serde_json::to_vec(&ObservationSetSubject {
        kind: "commissioning_observation_set_v1",
        records: &records,
    })
    .map(|bytes| Digest::blake3(&bytes))
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

impl CommissioningApproval {
    /// Exact typed subject approved by the institution owner.
    pub fn approved(&self) -> &ApprovedCommissioningSubject {
        &self.approved
    }
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

impl std::fmt::Display for CommissioningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingActiveGrant => {
                formatter.write_str("commissioning has no active workspace grant")
            }
            Self::AmbiguousActiveGrant => {
                formatter.write_str("commissioning has multiple active workspace grants")
            }
            Self::GrantAuthorityMismatch => {
                formatter.write_str("commissioner grant does not descend from workspace owner")
            }
            Self::EvidenceNotAdmitted => {
                formatter.write_str("commissioning evidence was not admitted by the trusted store")
            }
            Self::EvidenceSubjectMismatch => {
                formatter.write_str("commissioning evidence names a different subject")
            }
            Self::EvidenceProducerMismatch => {
                formatter.write_str("commissioning evidence was produced by the wrong principal")
            }
            Self::EvidenceDelegationMismatch => formatter
                .write_str("commissioning evidence was produced under the wrong delegation"),
            Self::EvidenceClassMismatch => {
                formatter.write_str("owner approval lacks human-authority evidence")
            }
            Self::EvidenceOutsideWindow => {
                formatter.write_str("commissioning evidence falls outside its trusted time window")
            }
            Self::MissingObservations => formatter.write_str("commissioning has no observations"),
            Self::UnexpectedApproval => {
                formatter.write_str("commissioning has a duplicate or unexpected approval")
            }
            Self::MissingRequiredApproval => {
                formatter.write_str("commissioning lacks a required typed approval")
            }
            Self::Encoding(_) => formatter.write_str("commissioning subject cannot be encoded"),
        }
    }
}

impl std::error::Error for CommissioningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}

impl CommissioningRecord {
    /// Resolve and validate a complete commissioning record.
    ///
    /// The constructor selects the sole active grant for the exact workspace,
    /// resolves every observation and approval from trusted admission, and
    /// requires owner approvals for the model, policy, complete generation
    /// input set, and exact unresolved-obligation set.
    ///
    /// # Errors
    ///
    /// Returns [`CommissioningError`] for missing/ambiguous authority,
    /// unadmitted or mismatched evidence, invalid time, or incomplete approval.
    ///
    /// Time: O((g + o + a) log(o + a)). Space: O(o + a).
    pub fn new(
        workspace: &InstitutionWorkspace,
        grants: &TrustedCommissionerGrantRegistry,
        evidence: &TrustedEvidenceRegistry,
        observation_ids: &BTreeSet<EvidenceId>,
        approval_ids: &BTreeSet<EvidenceId>,
        unresolved_obligations: BTreeSet<String>,
    ) -> Result<Self, CommissioningError> {
        let mut active = grants.active_for(&workspace.institution, &workspace.id);
        let grant = active
            .next()
            .ok_or(CommissioningError::MissingActiveGrant)?;
        if active.next().is_some() {
            return Err(CommissioningError::AmbiguousActiveGrant);
        }
        if grant.delegation.issuer != workspace.owner
            || grant.delegation.subject == workspace.owner
            || grant.delegation.parent.as_ref() != Some(&workspace.owner_delegation)
            || !grant.delegation.actions.contains(COMMISSION_ACTION)
            || !grant
                .delegation
                .resources
                .contains(&commissioning_workspace_resource(&workspace.id))
            || !grant
                .delegation
                .audience
                .contains(&commissioning_institution_audience(&workspace.institution))
        {
            return Err(CommissioningError::GrantAuthorityMismatch);
        }
        if observation_ids.is_empty() {
            return Err(CommissioningError::MissingObservations);
        }
        let grant_digest = grant.digest().map_err(CommissioningError::Encoding)?;
        let observations = observation_ids
            .iter()
            .map(|id| {
                evidence
                    .resolve(id)
                    .ok_or(CommissioningError::EvidenceNotAdmitted)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for observation in &observations {
            let expected = commissioning_observation_subject_digest(
                &workspace.institution,
                &workspace.id,
                &grant_digest,
                &observation.payload_digest,
            )
            .map_err(CommissioningError::Encoding)?;
            if observation.subject != expected {
                return Err(CommissioningError::EvidenceSubjectMismatch);
            }
            if observation.producer != grant.delegation.subject {
                return Err(CommissioningError::EvidenceProducerMismatch);
            }
            if observation.producer_delegation != grant.delegation.id {
                return Err(CommissioningError::EvidenceDelegationMismatch);
            }
            if observation.observed_at < grant.valid_from
                || observation.observed_at >= grant.delegation.expires_at
                || observation.observed_at > grants.as_of
            {
                return Err(CommissioningError::EvidenceOutsideWindow);
            }
        }
        let observations: Vec<_> = observations.into_iter().cloned().collect();
        let observation_set_digest = commissioning_observation_set_digest(&observations)
            .map_err(CommissioningError::Encoding)?;
        let generation_digest = workspace
            .approved_generation
            .digest()
            .map_err(CommissioningError::Encoding)?;
        let unresolved_obligations_digest = unresolved_obligations_digest(
            &workspace.institution,
            &workspace.id,
            &unresolved_obligations,
        )
        .map_err(CommissioningError::Encoding)?;
        let required_subjects = BTreeSet::from([
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: generation_digest,
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest.clone(),
            },
        ]);
        let expected_approvals = required_subjects
            .iter()
            .map(|subject| {
                commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    subject,
                    &observation_set_digest,
                )
                .map(|digest| (digest, subject.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(CommissioningError::Encoding)?;
        let last_observation = observations
            .iter()
            .map(|record| record.observed_at)
            .max()
            .ok_or(CommissioningError::MissingObservations)?;
        let mut approvals = Vec::new();
        let mut approved_subjects = BTreeSet::new();
        for id in approval_ids {
            let record = evidence
                .resolve(id)
                .ok_or(CommissioningError::EvidenceNotAdmitted)?;
            let approved = expected_approvals
                .get(&record.subject)
                .ok_or(CommissioningError::UnexpectedApproval)?;
            if !approved_subjects.insert(approved.clone()) {
                return Err(CommissioningError::UnexpectedApproval);
            }
            if record.producer != workspace.owner {
                return Err(CommissioningError::EvidenceProducerMismatch);
            }
            if record.producer_delegation != workspace.owner_delegation {
                return Err(CommissioningError::EvidenceDelegationMismatch);
            }
            if !matches!(record.independence, IndependenceClass::HumanAuthority) {
                return Err(CommissioningError::EvidenceClassMismatch);
            }
            if record.observed_at < last_observation || record.observed_at > grants.as_of {
                return Err(CommissioningError::EvidenceOutsideWindow);
            }
            approvals.push(CommissioningApproval {
                approved: approved.clone(),
                evidence: record.clone(),
            });
        }
        approvals.sort_by(|left, right| left.approved.cmp(&right.approved));
        if approved_subjects != required_subjects {
            return Err(CommissioningError::MissingRequiredApproval);
        }
        let workspace_digest = workspace.digest().map_err(CommissioningError::Encoding)?;
        Ok(Self {
            id: CommissioningRecordId::new(),
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            workspace_digest,
            captured_at: grants.as_of,
            commissioner_grant: grant.clone(),
            commissioner_grant_digest: grant_digest,
            observations,
            observation_set_digest,
            approvals,
            policy_bundle: workspace.policy_bundle.clone(),
            policy_digest: workspace.policy_digest.clone(),
            approved_generation: workspace.approved_generation.clone(),
            unresolved_obligations,
            unresolved_obligations_digest,
        })
    }

    /// Digest the canonical record for runtime-generation provenance binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the record cannot be represented.
    pub fn digest(&self) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| Digest::blake3(&bytes))
    }

    /// Record identity.
    pub fn id(&self) -> &CommissioningRecordId {
        &self.id
    }

    /// Institution being commissioned.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// Client-owned workspace identity.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Digest of the exact workspace snapshot.
    pub fn workspace_digest(&self) -> &Digest {
        &self.workspace_digest
    }

    /// Trusted grant/evidence snapshot time captured by this record.
    pub fn captured_at(&self) -> Timestamp {
        self.captured_at
    }

    /// Temporary commissioner principal derived from the admitted grant.
    pub fn commissioner(&self) -> &PrincipalId {
        &self.commissioner_grant.delegation.subject
    }

    /// Exact scoped commissioner delegation derived from the admitted grant.
    pub fn commissioner_delegation(&self) -> &DelegationId {
        &self.commissioner_grant.delegation.id
    }

    /// Digest of the exact admitted commissioner grant.
    pub fn commissioner_grant_digest(&self) -> &Digest {
        &self.commissioner_grant_digest
    }

    /// Complete admitted commissioner grant captured by this record.
    pub fn commissioner_grant(&self) -> &CommissionerGrantRecord {
        &self.commissioner_grant
    }

    /// Approved policy bundle identity.
    pub fn policy_bundle(&self) -> &PolicyBundleId {
        &self.policy_bundle
    }

    /// Digest of the approved policy bundle.
    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    /// Exact owner-approved specialization and build plan.
    pub fn approved_generation(&self) -> &ApprovedGenerationInputs {
        &self.approved_generation
    }

    /// Known obligations deliberately left unresolved and explicitly approved.
    pub fn unresolved_obligations(&self) -> &BTreeSet<String> {
        &self.unresolved_obligations
    }

    /// Digest of the exact owner-approved unresolved-obligation set.
    pub fn unresolved_obligations_digest(&self) -> &Digest {
        &self.unresolved_obligations_digest
    }
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::*;
    use crate::{
        AdapterId, DataClass, Effect, ResourceBudget,
        generation::{CommissioningCapability, ReproducibilityContract},
        institution::TrustDomainId,
        lifecycle::{DeploymentTopology, LifecycleProfile},
    };

    struct Fixture {
        workspace: InstitutionWorkspace,
        as_of: Timestamp,
        grant: CommissionerGrantRecord,
        observation: EvidenceRecord,
        approvals: Vec<EvidenceRecord>,
        obligations: BTreeSet<String>,
    }

    #[expect(
        clippy::expect_used,
        reason = "canonical trust-domain fixture must fail loudly if validation drifts"
    )]
    fn workspace() -> InstitutionWorkspace {
        InstitutionWorkspace {
            id: InstitutionWorkspaceId::new(),
            institution: InstitutionId::new(),
            trust_domain: "client-a:commissioning"
                .parse::<TrustDomainId>()
                .expect("fixture trust domain is canonical"),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"approved model"),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"approved policy"),
            approved_generation: ApprovedGenerationInputs {
                source_digest: Digest::blake3(b"source"),
                lifecycle: LifecycleProfile::Operational,
                topology: DeploymentTopology::ClientControlledSingleTenant,
                schema_digests: BTreeMap::from([(
                    "operation".to_string(),
                    Digest::blake3(b"schema"),
                )]),
                adapter_digests: BTreeMap::from([(AdapterId::new(), Digest::blake3(b"adapter"))]),
                pack_digests: BTreeMap::new(),
                component_digests: BTreeMap::new(),
                excluded_commissioning_capabilities: BTreeSet::from([
                    CommissioningCapability::GenericReconnaissance,
                    CommissioningCapability::InstitutionAuthoring,
                    CommissioningCapability::AdapterDevelopment,
                    CommissioningCapability::PolicyAuthoring,
                    CommissioningCapability::GenerationDerivation,
                ]),
                specializer_digest: Digest::blake3(b"specializer"),
                toolchain_digest: Digest::blake3(b"toolchain"),
                reproducibility: ReproducibilityContract::Deterministic,
            },
            secret_references: BTreeSet::new(),
        }
    }

    fn grant(workspace: &InstitutionWorkspace, as_of: Timestamp) -> CommissionerGrantRecord {
        CommissionerGrantRecord {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            valid_from: as_of - SignedDuration::from_mins(5),
            revoked_at: None,
            delegation: Delegation {
                id: DelegationId::new(),
                issuer: workspace.owner.clone(),
                subject: PrincipalId::new(),
                parent: Some(workspace.owner_delegation.clone()),
                actions: BTreeSet::from([COMMISSION_ACTION.to_string()]),
                resources: BTreeSet::from([commissioning_workspace_resource(&workspace.id)]),
                effects: BTreeSet::from([Effect::ReadExternalSystem]),
                data_classes: BTreeSet::from([DataClass::Internal]),
                audience: BTreeSet::from([commissioning_institution_audience(
                    &workspace.institution,
                )]),
                expires_at: as_of + SignedDuration::from_hours(1),
                budget: ResourceBudget {
                    wall_ms: Some(60_000),
                    cpu_ms: Some(10_000),
                    memory_bytes: Some(64 * 1024 * 1024),
                    io_bytes: Some(1024 * 1024),
                    network_bytes: Some(1024 * 1024),
                    external_cost_microunits: Some(0),
                },
            },
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "commissioning evidence fixtures must encode their exact grant subject"
    )]
    fn observation(
        workspace: &InstitutionWorkspace,
        grant: &CommissionerGrantRecord,
        as_of: Timestamp,
    ) -> EvidenceRecord {
        let payload_digest = Digest::blake3(b"bounded observation");
        EvidenceRecord {
            id: EvidenceId::new(),
            subject: commissioning_observation_subject_digest(
                &workspace.institution,
                &workspace.id,
                &grant.digest().expect("fixture grant encodes"),
                &payload_digest,
            )
            .expect("fixture observation subject encodes"),
            producer: grant.delegation.subject.clone(),
            producer_delegation: grant.delegation.id.clone(),
            method: "bounded read-only discovery".to_string(),
            payload_digest,
            observed_at: as_of - SignedDuration::from_mins(2),
            independence: IndependenceClass::SelfReported,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "approval fixtures bind exact typed subjects to admitted observations"
    )]
    fn approvals(
        workspace: &InstitutionWorkspace,
        observation: &EvidenceRecord,
        obligations: &BTreeSet<String>,
        as_of: Timestamp,
    ) -> Vec<EvidenceRecord> {
        let observation_set_digest =
            commissioning_observation_set_digest(std::slice::from_ref(observation))
                .expect("fixture observation set encodes");
        let subjects = [
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: workspace
                    .approved_generation
                    .digest()
                    .expect("fixture generation inputs encode"),
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest(
                    &workspace.institution,
                    &workspace.id,
                    obligations,
                )
                .expect("fixture obligations encode"),
            },
        ];
        subjects
            .iter()
            .map(|subject| EvidenceRecord {
                id: EvidenceId::new(),
                subject: commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    subject,
                    &observation_set_digest,
                )
                .expect("fixture approval subject encodes"),
                producer: workspace.owner.clone(),
                producer_delegation: workspace.owner_delegation.clone(),
                method: "institution-owner approval".to_string(),
                payload_digest: Digest::blake3(b"signed owner approval"),
                observed_at: as_of - SignedDuration::from_mins(1),
                independence: IndependenceClass::HumanAuthority,
            })
            .collect()
    }

    fn fixture(obligations: BTreeSet<String>) -> Fixture {
        let workspace = workspace();
        let as_of = Timestamp::now();
        let grant = grant(&workspace, as_of);
        let observation = observation(&workspace, &grant, as_of);
        let approvals = approvals(&workspace, &observation, &obligations, as_of);
        Fixture {
            workspace,
            as_of,
            grant,
            observation,
            approvals,
            obligations,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "trusted fixture registries must reject accidental duplicate identities"
    )]
    fn record(
        fixture: &Fixture,
        grants: impl IntoIterator<Item = CommissionerGrantRecord>,
        evidence: impl IntoIterator<Item = EvidenceRecord>,
        obligations: BTreeSet<String>,
    ) -> Result<CommissioningRecord, CommissioningError> {
        let grant_registry =
            TrustedCommissionerGrantRegistry::from_trusted_bootstrap(fixture.as_of, grants)
                .expect("fixture grant registry is coherent");
        let evidence: Vec<_> = evidence.into_iter().collect();
        let observation_ids = BTreeSet::from([fixture.observation.id.clone()]);
        let approval_ids = fixture
            .approvals
            .iter()
            .map(|approval| approval.id.clone())
            .collect();
        let evidence_registry = TrustedEvidenceRegistry::from_trusted_bootstrap(evidence)
            .expect("fixture evidence identities are unique");
        CommissioningRecord::new(
            &fixture.workspace,
            &grant_registry,
            &evidence_registry,
            &observation_ids,
            &approval_ids,
            obligations,
        )
    }

    fn fixture_evidence(fixture: &Fixture) -> Vec<EvidenceRecord> {
        std::iter::once(fixture.observation.clone())
            .chain(fixture.approvals.clone())
            .collect()
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "valid commissioning fixture must prove exact trusted resolution"
    )]
    fn record_resolves_full_grant_evidence_and_obligations() {
        let fixture = fixture(BTreeSet::from(["retain legacy audit log".to_string()]));
        let record = record(
            &fixture,
            [fixture.grant.clone()],
            fixture_evidence(&fixture),
            fixture.obligations.clone(),
        )
        .expect("exact trusted commissioning inputs must validate");
        assert_eq!(record.commissioner(), &fixture.grant.delegation.subject);
        assert_eq!(
            record.commissioner_delegation(),
            &fixture.grant.delegation.id
        );
        assert_eq!(record.unresolved_obligations(), &fixture.obligations);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "rebound evidence fixture must preserve an exact grant identity"
    )]
    fn unadmitted_or_rebound_observations_are_rejected() {
        let fixture = fixture(BTreeSet::new());
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                fixture.approvals.clone(),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceNotAdmitted)
        ));

        let mut rebound = fixture.observation.clone();
        rebound.payload_digest = Digest::blake3(b"rebound payload");
        rebound.subject = commissioning_observation_subject_digest(
            &fixture.workspace.institution,
            &fixture.workspace.id,
            &fixture.grant.digest().expect("fixture grant encodes"),
            &rebound.payload_digest,
        )
        .expect("rebound observation subject encodes");
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                std::iter::once(rebound).chain(fixture.approvals.clone()),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::UnexpectedApproval)
        ));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "observation-set identity must be invariant to caller iteration order"
    )]
    fn observation_set_digest_has_canonical_record_order() {
        let fixture = fixture(BTreeSet::new());
        let first = fixture.observation;
        let mut second = first.clone();
        second.id = EvidenceId::new();
        second.payload_digest = Digest::blake3(b"second observation payload");

        let forward = commissioning_observation_set_digest(&[first.clone(), second.clone()])
            .expect("forward observation set encodes");
        let reverse = commissioning_observation_set_digest(&[second, first])
            .expect("reverse observation set encodes");
        assert_eq!(
            forward, reverse,
            "set identity cannot depend on slice order"
        );
    }

    #[test]
    fn grant_authority_and_singular_active_set_fail_closed() {
        let fixture = fixture(BTreeSet::new());
        let mut mislabeled = fixture.grant.clone();
        mislabeled.workspace = InstitutionWorkspaceId::new();
        assert!(matches!(
            TrustedCommissionerGrantRegistry::from_trusted_bootstrap(fixture.as_of, [mislabeled]),
            Err(CommissionerGrantRegistryError::ScopeMismatch)
        ));

        let mut second = fixture.grant.clone();
        second.delegation.id = DelegationId::new();
        second.delegation.subject = PrincipalId::new();
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone(), second],
                fixture_evidence(&fixture),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::AmbiguousActiveGrant)
        ));

        let mut wrong_issuer = fixture.grant.clone();
        wrong_issuer.delegation.issuer = PrincipalId::new();
        assert!(matches!(
            record(
                &fixture,
                [wrong_issuer],
                fixture_evidence(&fixture),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::GrantAuthorityMismatch)
        ));
    }

    #[test]
    fn observation_axes_and_time_are_exact() {
        let fixture = fixture(BTreeSet::new());
        let mut wrong_producer = fixture.observation.clone();
        wrong_producer.producer = PrincipalId::new();
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                std::iter::once(wrong_producer).chain(fixture.approvals.clone()),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceProducerMismatch)
        ));

        let mut expired = fixture.observation.clone();
        expired.observed_at = fixture.grant.delegation.expires_at;
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                std::iter::once(expired).chain(fixture.approvals.clone()),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceOutsideWindow)
        ));
    }

    #[test]
    fn owner_approval_axes_and_class_are_exact() {
        let fixture = fixture(BTreeSet::new());
        let mut wrong_owner = fixture.approvals.clone();
        wrong_owner[0].producer = PrincipalId::new();
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                std::iter::once(fixture.observation.clone()).chain(wrong_owner),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceProducerMismatch)
        ));

        let mut self_reported = fixture.approvals.clone();
        self_reported[0].independence = IndependenceClass::SelfReported;
        assert!(matches!(
            record(
                &fixture,
                [fixture.grant.clone()],
                std::iter::once(fixture.observation.clone()).chain(self_reported),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceClassMismatch)
        ));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "explicit empty-obligation approval must remain constructible"
    )]
    fn obligations_cannot_change_or_disappear_after_approval() {
        let populated = fixture(BTreeSet::from(["retain audit log".to_string()]));
        assert!(matches!(
            record(
                &populated,
                [populated.grant.clone()],
                fixture_evidence(&populated),
                BTreeSet::new(),
            ),
            Err(CommissioningError::UnexpectedApproval)
        ));

        let empty = fixture(BTreeSet::new());
        record(
            &empty,
            [empty.grant.clone()],
            fixture_evidence(&empty),
            BTreeSet::new(),
        )
        .expect("empty obligations require and accept their exact explicit approval");
    }

    #[test]
    fn altered_grant_scope_invalidates_existing_observations() {
        let fixture = fixture(BTreeSet::new());
        let mut changed = fixture.grant.clone();
        changed
            .delegation
            .effects
            .insert(Effect::WriteExternalSystem);
        assert!(matches!(
            record(
                &fixture,
                [changed],
                fixture_evidence(&fixture),
                fixture.obligations.clone(),
            ),
            Err(CommissioningError::EvidenceSubjectMismatch)
        ));
    }
}
