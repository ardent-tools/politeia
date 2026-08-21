//! Institution ownership, trust-domain, role, and workspace contracts.

use crate::canonical::{CanonicalError, to_canonical_bytes};
use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    DelegationId, Digest, InstitutionId, InstitutionWorkspaceId, PolicyBundleId, PrincipalId,
    generation::ApprovedGenerationInputs,
};

/// Stable identifier for a client-controlled trust boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct TrustDomainId(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = "^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    )]
    String,
);

/// A trust-domain identifier was empty, too long, or non-canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTrustDomainId;

impl std::fmt::Display for InvalidTrustDomainId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "trust-domain identity must be 1..=128 ASCII letters, digits, '.', '_', ':', or '-'",
        )
    }
}

impl std::error::Error for InvalidTrustDomainId {}

impl TrustDomainId {
    /// The canonical trust-domain identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TrustDomainId {
    type Error = InvalidTrustDomainId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let valid = (1..=128).contains(&bytes.len())
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-')
            });
        valid.then_some(Self(value)).ok_or(InvalidTrustDomainId)
    }
}

impl std::str::FromStr for TrustDomainId {
    type Err = InvalidTrustDomainId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_string())
    }
}

impl<'de> Deserialize<'de> for TrustDomainId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// A descriptive role within one institution.
///
/// A role label never grants authority. Protected work still requires an
/// exact, valid delegation and policy decision.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum InstitutionRole {
    /// May establish or alter constitutional commitments.
    InstitutionOwner,
    /// Temporarily discovers, models, and prepares the institution.
    Commissioner,
    /// Performs bounded post-handoff maintenance or recommissioning.
    Maintainer,
    /// Performs bounded institutional work.
    Worker,
    /// Performs a designated assurance obligation.
    Verifier,
}

/// A descriptive role assignment backed by an explicit delegation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleAssignment {
    /// Institution in which the role is described.
    pub institution: InstitutionId,
    /// Principal occupying the role.
    pub principal: PrincipalId,
    /// Descriptive role; not an ambient grant.
    pub role: InstitutionRole,
    /// Exact delegation that carries any authority associated with the role.
    pub delegation: DelegationId,
}

/// A thing that belongs to exactly one institution workspace.
///
/// WHY a trait rather than a field each component compares for itself: workspace
/// scoping is one rule. A component that carries its own copy of the identity is
/// a component that can disagree with its neighbours about whose institution it
/// serves, and nothing would say which of them was right.
pub trait WorkspaceScoped {
    /// The workspace this belongs to.
    fn workspace(&self) -> &InstitutionWorkspaceId;
}

/// One institution's boundary: everything scoped to a single workspace.
///
/// `docs/16-DATA_GOVERNANCE.md` puts institution-owned material, its
/// classifications, its evidence and its egress inside one client-controlled
/// trust boundary. This is that boundary as a type: it holds the identity once,
/// and its components are the things that identity governs.
///
/// WHY the components do not carry the identity themselves: three copies of a
/// workspace id are three chances to disagree, and the disagreement is silent —
/// each component's own check passes against its own copy. Asking the boundary
/// means there is one answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstitutionBoundary<Outbox> {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    outbox: Outbox,
}

impl<Outbox> InstitutionBoundary<Outbox> {
    /// Establish a boundary around one workspace.
    pub fn new(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        outbox: Outbox,
    ) -> Self {
        Self {
            institution,
            workspace,
            outbox,
        }
    }

    /// The institution this boundary serves.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// The workspace this boundary is scoped to.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// What may leave this boundary.
    pub fn outbox(&self) -> &Outbox {
        &self.outbox
    }

    /// Whether this boundary owns the given item.
    ///
    /// The one place the cross-institution question is asked. Everything that
    /// refuses foreign material refuses it by asking here, so the rule cannot be
    /// implemented two ways.
    pub fn owns<T: WorkspaceScoped>(&self, item: &T) -> bool {
        item.workspace() == &self.workspace
    }
}

/// Client-owned semantic input boundary for commissioning and specialization.
///
/// This manifest names digests and secret references, never secret values or
/// a repository/filesystem layout.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstitutionWorkspace {
    /// Stable workspace identity.
    pub id: InstitutionWorkspaceId,
    /// Institution whose private facts and inputs the workspace owns.
    pub institution: InstitutionId,
    /// Client-controlled trust boundary that stores the workspace.
    pub trust_domain: TrustDomainId,
    /// Institution owner responsible for constitutional approvals.
    pub owner: PrincipalId,
    /// Delegation proving the owner's authority for this workspace snapshot.
    pub owner_delegation: DelegationId,
    /// Digest of the approved institutional model.
    pub approved_model_digest: Digest,
    /// Approved policy bundle identity.
    pub policy_bundle: PolicyBundleId,
    /// Digest of the exact approved policy bundle.
    pub policy_digest: Digest,
    /// Exact owner-approved specialization and build inputs.
    pub approved_generation: ApprovedGenerationInputs,
    /// Approved references to secrets; values never appear in this manifest.
    pub secret_references: BTreeSet<String>,
}

impl std::fmt::Debug for InstitutionWorkspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstitutionWorkspace")
            .field("id", &self.id)
            .field("institution", &self.institution)
            .field("trust_domain", &self.trust_domain)
            .field("owner", &self.owner)
            .field("owner_delegation", &self.owner_delegation)
            .field("approved_model_digest", &self.approved_model_digest)
            .field("policy_bundle", &self.policy_bundle)
            .field("policy_digest", &self.policy_digest)
            .field(
                "component_count",
                &self.approved_generation.component_digests.len(),
            )
            .field("secret_reference_count", &self.secret_references.len())
            .finish()
    }
}

impl InstitutionWorkspace {
    /// Digest the canonical workspace manifest for generation binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed manifest cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the canonical manifest size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        to_canonical_bytes(self).map(|bytes| Digest::blake3(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_identity_rejects_ambiguous_strings() {
        for invalid in ["", " leading", "client/a", "client a"] {
            assert!(
                invalid.parse::<TrustDomainId>().is_err(),
                "ambiguous trust-domain identity {invalid:?} must fail closed"
            );
        }
        assert!(
            "client-a:production".parse::<TrustDomainId>().is_ok(),
            "a canonical scoped trust-domain identity must be accepted"
        );
    }
}
