//! Validated commissioning approval and provenance assembly.

use crate::canonical::CanonicalError;
use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;

use crate::{
    CommissioningRecordId, DelegationId, Digest, DigestDomain, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId,
    evidence::{IndependenceClass, TrustedEvidenceRegistry},
    generation::ApprovedGenerationInputs,
    institution::InstitutionWorkspace,
};

use super::{
    ApprovedCommissioningSubject, COMMISSION_ACTION, CommissionerGrantRecord,
    CommissioningApproval, CommissioningError, CommissioningRecord,
    TrustedCommissionerGrantRegistry, commissioning_approval_subject_digest,
    commissioning_institution_audience, commissioning_observation_set_digest,
    commissioning_observation_subject_digest, commissioning_workspace_resource,
    unresolved_obligations_digest,
};

impl CommissioningApproval {
    /// Exact typed subject approved by the institution owner.
    pub fn approved(&self) -> &ApprovedCommissioningSubject {
        &self.approved
    }
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
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::CommissioningRecord, self)
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
