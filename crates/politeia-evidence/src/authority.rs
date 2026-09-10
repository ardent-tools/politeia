//! Admitted, directly delegated authority for assurance work.
//!
//! Signature admission answers who made a statement. This module answers the
//! separate semantic question: whether that signer received the exact action,
//! resource, institution, and lifetime needed to make it authoritative.

use jiff::Timestamp;
use politeia_core::trust::{AdmissionKind, Admitted};
use politeia_core::{Delegation, InstitutionId, InstitutionWorkspaceId, PrincipalId};

/// Trusted coordinates against which a direct assurance grant is resolved.
///
/// WHY this is an explicit input: an admitted delegation is authenticated data,
/// not ambient authority. The installed institution owner and decision time
/// must come from the host's trusted workspace snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityContext {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    institution_owner: PrincipalId,
    at: Timestamp,
}

impl AuthorityContext {
    /// Bind authority resolution to one installed workspace owner and instant.
    pub fn new(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        institution_owner: PrincipalId,
        at: Timestamp,
    ) -> Self {
        Self {
            institution,
            workspace,
            institution_owner,
            at,
        }
    }

    /// The installed institution identity.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// The installed workspace identity.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// The installed institution owner that may issue direct grants.
    pub fn institution_owner(&self) -> &PrincipalId {
        &self.institution_owner
    }

    /// The trusted instant at which the grant must be active.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// One authenticated direct grant that satisfies an exact semantic need.
///
/// The fields remain private so callers cannot promote an admitted delegation
/// merely by pairing it with strings that look like an authority requirement.
#[derive(Clone, Debug)]
pub struct DirectGrant<'admission> {
    admission: &'admission Admitted<Delegation>,
    valid_at: Timestamp,
}

impl<'admission> DirectGrant<'admission> {
    /// Resolve a directly owner-issued grant for one signer, action, and resource.
    ///
    /// The grant axes are exact singleton sets. A broad delegation cannot be
    /// smuggled through a narrow assurance operation simply because it happens
    /// to contain the requested token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityRefusal`] when authentication scope, issuer/subject,
    /// lifetime, or any semantic authority axis differs from the requirement.
    pub fn admit(
        admission: &'admission Admitted<Delegation>,
        context: &AuthorityContext,
        subject: &PrincipalId,
        action: &str,
        resource: &str,
    ) -> Result<Self, AuthorityRefusal> {
        if admission.kind() != AdmissionKind::Delegation {
            return Err(AuthorityRefusal::UnexpectedAdmissionKind);
        }
        if admission.institution() != context.institution() {
            return Err(AuthorityRefusal::ForeignInstitution);
        }
        if admission.workspace() != context.workspace() {
            return Err(AuthorityRefusal::ForeignWorkspace);
        }

        let delegation = admission.payload();
        if admission.signer() != &delegation.issuer {
            return Err(AuthorityRefusal::SignerIssuerMismatch);
        }
        if &delegation.issuer != context.institution_owner() {
            return Err(AuthorityRefusal::UntrustedIssuer);
        }
        if delegation.parent.is_some() {
            return Err(AuthorityRefusal::IndirectGrant);
        }
        if delegation.issuer == delegation.subject {
            return Err(AuthorityRefusal::SelfDelegation);
        }
        if &delegation.subject != subject {
            return Err(AuthorityRefusal::SubjectMismatch);
        }
        if delegation.is_expired(context.at()) {
            return Err(AuthorityRefusal::Expired);
        }

        let expected_action = std::collections::BTreeSet::from([action.to_string()]);
        if delegation.actions != expected_action {
            return Err(AuthorityRefusal::ActionScopeMismatch);
        }
        let expected_resource = std::collections::BTreeSet::from([resource.to_string()]);
        if delegation.resources != expected_resource {
            return Err(AuthorityRefusal::ResourceScopeMismatch);
        }
        let expected_audience =
            std::collections::BTreeSet::from([institution_audience(context.institution())]);
        if delegation.audience != expected_audience {
            return Err(AuthorityRefusal::AudienceScopeMismatch);
        }
        if !delegation.effects.is_empty() {
            return Err(AuthorityRefusal::EffectScopeMismatch);
        }
        if !delegation.data_classes.is_empty() {
            return Err(AuthorityRefusal::DataScopeMismatch);
        }

        Ok(Self {
            admission,
            valid_at: context.at(),
        })
    }

    /// The admitted delegation that carries the exact grant.
    pub fn admission(&self) -> &'admission Admitted<Delegation> {
        self.admission
    }

    /// The trusted instant at which this grant was resolved.
    pub fn valid_at(&self) -> Timestamp {
        self.valid_at
    }
}

/// Why an admitted delegation does not carry an exact direct grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityRefusal {
    /// The admitted payload was not admitted for delegation use.
    UnexpectedAdmissionKind,
    /// The delegation was admitted under another institution.
    ForeignInstitution,
    /// The delegation was admitted under another workspace.
    ForeignWorkspace,
    /// The authenticated signer is not the delegation's issuer.
    SignerIssuerMismatch,
    /// The issuer is not the installed institution owner.
    UntrustedIssuer,
    /// This bounded boundary accepts direct owner grants only.
    IndirectGrant,
    /// The signer attempted to delegate authority to itself.
    SelfDelegation,
    /// The delegation names another recipient.
    SubjectMismatch,
    /// The delegation was expired at the trusted decision instant.
    Expired,
    /// The grant's action set was not the exact required singleton.
    ActionScopeMismatch,
    /// The grant's resource set was not the exact required singleton.
    ResourceScopeMismatch,
    /// The grant's audience was not the exact institution singleton.
    AudienceScopeMismatch,
    /// An assurance-only grant carried effect authority.
    EffectScopeMismatch,
    /// An assurance-only grant carried data authority.
    DataScopeMismatch,
}

impl std::fmt::Display for AuthorityRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnexpectedAdmissionKind => "payload was not admitted as a delegation",
            Self::ForeignInstitution => "delegation belongs to another institution",
            Self::ForeignWorkspace => "delegation belongs to another workspace",
            Self::SignerIssuerMismatch => "delegation signer is not its issuer",
            Self::UntrustedIssuer => "delegation issuer is not the installed institution owner",
            Self::IndirectGrant => "assurance authority is not a direct owner grant",
            Self::SelfDelegation => "delegation is self-issued",
            Self::SubjectMismatch => "delegation names another subject",
            Self::Expired => "delegation is expired at the trusted decision instant",
            Self::ActionScopeMismatch => "delegation action scope is not exact",
            Self::ResourceScopeMismatch => "delegation resource scope is not exact",
            Self::AudienceScopeMismatch => "delegation audience scope is not exact",
            Self::EffectScopeMismatch => "assurance delegation carries effect authority",
            Self::DataScopeMismatch => "assurance delegation carries data authority",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuthorityRefusal {}

/// Canonical delegation audience for one institution.
pub fn institution_audience(institution: &InstitutionId) -> String {
    format!("institution:{}", institution.0)
}
