//! Signed waiver admission and exact delegated authority.

use jiff::Timestamp;
use politeia_core::trust::{AdmissionKind, Admitted};
use politeia_core::{Delegation, InstitutionId, InstitutionWorkspaceId, PrincipalId};
use politeia_evidence::authority::{AuthorityContext, AuthorityRefusal, DirectGrant};

use crate::Waiver;

/// Semantic action delegated to a policy-waiver signer.
pub const WAIVE_POLICY_BINDING_ACTION: &str = "waive-policy-binding";

/// Exact delegation resource for one policy binding.
pub fn policy_binding_resource(binding: &str) -> String {
    format!("policy-binding:{binding}")
}

/// An authenticated waiver backed by a direct, exact owner grant.
///
/// WHY this is the evaluator input instead of [`Waiver`]: a signed exception
/// proves who requested it, while this type additionally proves that signer
/// was delegated the exact binding authority and lifetime it consumes.
#[derive(Clone, Debug)]
pub struct DelegatedWaiver<'admission> {
    admission: &'admission Admitted<Waiver>,
    grant: DirectGrant<'admission>,
}

impl<'admission> DelegatedWaiver<'admission> {
    /// Admit one waiver under exact, direct institution-owner authority.
    ///
    /// # Errors
    ///
    /// Returns [`WaiverAdmissionRefusal`] when authentication scope, delegated
    /// authority, or expiry does not support the signed exception.
    pub fn admit(
        admission: &'admission Admitted<Waiver>,
        authority: &'admission Admitted<Delegation>,
        context: &AuthorityContext,
    ) -> Result<Self, WaiverAdmissionRefusal> {
        if admission.kind() != AdmissionKind::Waiver {
            return Err(WaiverAdmissionRefusal::UnexpectedAdmissionKind);
        }
        if admission.institution() != context.institution() {
            return Err(WaiverAdmissionRefusal::ForeignInstitution);
        }
        if admission.workspace() != context.workspace() {
            return Err(WaiverAdmissionRefusal::ForeignWorkspace);
        }
        let waiver = admission.payload();
        if context.at() >= waiver.expires_at {
            return Err(WaiverAdmissionRefusal::Expired);
        }
        let resource = policy_binding_resource(&waiver.binding_id);
        let grant = DirectGrant::admit(
            authority,
            context,
            admission.signer(),
            WAIVE_POLICY_BINDING_ACTION,
            &resource,
        )
        .map_err(WaiverAdmissionRefusal::Authority)?;
        if waiver.expires_at > grant.admission().payload().expires_at {
            return Err(WaiverAdmissionRefusal::OutlivesAuthority);
        }
        Ok(Self { admission, grant })
    }

    /// The authenticated waiver payload.
    pub fn waiver(&self) -> &Waiver {
        self.admission.payload()
    }

    /// The authenticated waiver signer.
    pub fn signer(&self) -> &PrincipalId {
        self.admission.signer()
    }

    /// Institution under which the waiver was admitted.
    pub fn institution(&self) -> &InstitutionId {
        self.admission.institution()
    }

    /// Workspace under which the waiver was admitted.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        self.admission.workspace()
    }

    /// Trusted instant at which the authority and expiry were resolved.
    pub fn valid_at(&self) -> Timestamp {
        self.grant.valid_at()
    }
}

/// Why a signed waiver did not become an authorized exception.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaiverAdmissionRefusal {
    /// The payload was admitted for another semantic use.
    UnexpectedAdmissionKind,
    /// The waiver belongs to another institution.
    ForeignInstitution,
    /// The waiver belongs to another workspace.
    ForeignWorkspace,
    /// The waiver was already expired at the trusted instant.
    Expired,
    /// The waiver expiry exceeds its delegation expiry.
    OutlivesAuthority,
    /// The direct semantic grant was invalid.
    Authority(AuthorityRefusal),
}

impl std::fmt::Display for WaiverAdmissionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedAdmissionKind => {
                formatter.write_str("waiver payload was admitted for another use")
            }
            Self::ForeignInstitution => {
                formatter.write_str("waiver belongs to another institution")
            }
            Self::ForeignWorkspace => formatter.write_str("waiver belongs to another workspace"),
            Self::Expired => formatter.write_str("waiver is expired at the trusted instant"),
            Self::OutlivesAuthority => {
                formatter.write_str("waiver outlives its delegated authority")
            }
            Self::Authority(refusal) => write!(formatter, "waiver authority refused: {refusal}"),
        }
    }
}

impl std::error::Error for WaiverAdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(refusal) => Some(refusal),
            _ => None,
        }
    }
}
