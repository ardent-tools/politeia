//! Commissioner grant identity and trusted-registry behavior.

use super::*;

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

    /// Iterate grants active for one exact institution workspace at snapshot time.
    ///
    /// Time: O(g). Space: O(1), where g is the admitted grant count.
    pub(super) fn active_for<'a>(
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
