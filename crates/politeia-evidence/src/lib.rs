//! politeia-evidence: evidence, verification, and attestation records.
//!
//! Evidence carries claims; attestation binds a verified subject to the exact
//! policy, runtime, adapter, and delegation identities it was verified under.

#![deny(missing_docs)]

pub mod assessment;
pub mod assurance;

use std::collections::BTreeSet;

use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{
    AdapterId, CommissioningRecordId, DelegationId, Digest, DigestDomain, EvidenceId,
    InstitutionId, InstitutionWorkspaceId, PolicyBundleId, PrincipalId, RuntimeGenerationId,
    generation::{RuntimeGeneration, RuntimeGenerationError},
    institution::InstitutionWorkspace,
    lifecycle::LifecycleProfile,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use politeia_core::{
    commissioning::{CommissioningApproval, CommissioningRecord, TrustedCommissionerGrantRegistry},
    evidence::{EvidenceRecord, EvidenceRegistryError, IndependenceClass, TrustedEvidenceRegistry},
};

#[derive(Serialize)]
struct CommissionerRevocationSubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    commissioning_record: &'a CommissioningRecordId,
    commissioner_grant_digest: &'a Digest,
}

#[derive(Serialize)]
struct OperationalContinuitySubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    generation: &'a RuntimeGenerationId,
}

/// Digest the exact subject that proves one commissioner delegation ended.
///
/// # Errors
///
/// Returns the JSON encoding failure if the typed subject cannot be represented.
///
/// Time: O(n). Space: O(n), where n is the encoded subject size.
pub fn commissioner_revocation_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    commissioning_record: &CommissioningRecordId,
    commissioner_grant_digest: &Digest,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(&CommissionerRevocationSubject {
        kind: "commissioner_revocation_v1",
        institution,
        workspace,
        commissioning_record,
        commissioner_grant_digest,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Digest the exact subject that proves an operational generation remained live.
///
/// # Errors
///
/// Returns the JSON encoding failure if the typed subject cannot be represented.
///
/// Time: O(n). Space: O(n), where n is the encoded subject size.
pub fn operational_continuity_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    generation: &RuntimeGenerationId,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(&OperationalContinuitySubject {
        kind: "operational_continuity",
        institution,
        workspace,
        generation,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// An independent or designated evaluation of evidence against a subject.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// Digest of the verified subject.
    pub subject: Digest,
    /// The verifying principal.
    pub verifier: PrincipalId,
    /// The evidence records the verdict relies on.
    pub evidence: Vec<EvidenceId>,
    /// Whether the subject passed.
    pub passed: bool,
    /// The verifier's independence class.
    pub independence: IndependenceClass,
}

/// The exact identities one attestation binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationStatement {
    /// Digest of the attested subject.
    pub subject: Digest,
    /// The attesting verifier.
    pub verifier: PrincipalId,
    /// The policy bundle identity.
    pub policy: PolicyBundleId,
    /// The runtime generation identity.
    pub runtime: RuntimeGenerationId,
    /// The adapter identity.
    pub adapter: AdapterId,
    /// The delegation identity the work ran under.
    pub delegation: DelegationId,
    /// The evidence records bound into the attestation.
    pub evidence: Vec<EvidenceId>,
}

impl AttestationStatement {
    /// Digest the exact identities this statement binds.
    ///
    /// # Errors
    ///
    /// Returns the canonical-encoding failure if the statement cannot be
    /// represented.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::AttestationStatement, self)
    }
}

/// Why an attestation may not be issued or admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationRefusal {
    /// The verification it rests on did not pass.
    VerificationFailed,
    /// The verification cites no evidence.
    ///
    /// A verdict resting on nothing is an opinion. `docs/06-POLICY_COMPILER.md`
    /// separates the detector from the claim precisely so that a verdict has to
    /// name what it read.
    NoEvidence,
    /// The verifier reported on itself.
    ///
    /// `AGENTS.md`: do not allow the actor being judged to satisfy an
    /// independence requirement by self-certification. `IndependenceClass`
    /// already documents `SelfReported` as never satisfying the obligation;
    /// this is where that stops being documentation.
    SelfCertified,
    /// The verifier is the principal whose work was judged.
    ///
    /// Distinct from the class: a verifier can honestly record itself as an
    /// independent service and still *be* the actor under judgement, and the
    /// class is a claim while this is a comparison.
    VerifierIsTheSubjectActor,
    /// The recorded statement digest is not the digest of the statement.
    StatementDigestMismatch,
    /// The statement could not be encoded.
    Encoding(String),
}

impl std::fmt::Display for AttestationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationRefusal::VerificationFailed => {
                formatter.write_str("the verification did not pass")
            }
            AttestationRefusal::NoEvidence => {
                formatter.write_str("the verification cites no evidence")
            }
            AttestationRefusal::SelfCertified => {
                formatter.write_str("a self-reported verification cannot be attested")
            }
            AttestationRefusal::VerifierIsTheSubjectActor => {
                formatter.write_str("the verifier is the principal whose work was judged")
            }
            AttestationRefusal::StatementDigestMismatch => {
                formatter.write_str("the recorded digest is not the digest of the statement")
            }
            AttestationRefusal::Encoding(message) => {
                write!(formatter, "the statement cannot be encoded: {message}")
            }
        }
    }
}

impl std::error::Error for AttestationRefusal {}

/// A durable statement binding a verified subject to the exact policy,
/// runtime, adapter, delegation, and evidence identities it was verified
/// under.
///
/// An attestation is not portable to another subject, and that is enforced
/// rather than asserted: the statement digest covers the subject along with
/// every other bound identity, and both [`Attestation::issue`] and the
/// deserializer recompute it. Swapping the subject leaves a digest that no
/// longer describes the statement it sits beside.
///
/// WHY the digest is not a public field: a value the caller supplies is a value
/// the caller can supply wrongly, and a false one is indistinguishable from a
/// true one at every call site that reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    statement: AttestationStatement,
    statement_digest: Digest,
}

impl Attestation {
    /// Issue an attestation over a passed, independent verification.
    ///
    /// `subject_actor` is the principal whose work was judged, which the
    /// verifier may not be.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationRefusal`] when the verification did not pass, cites
    /// no evidence, is self-reported, or was performed by the actor under
    /// judgement — and when the statement cannot be encoded.
    ///
    /// Time: O(n) in the statement size. Space: O(n).
    pub fn issue(
        verification: &Verification,
        subject_actor: &PrincipalId,
        policy: PolicyBundleId,
        runtime: RuntimeGenerationId,
        adapter: AdapterId,
        delegation: DelegationId,
    ) -> Result<Self, AttestationRefusal> {
        if !verification.passed {
            return Err(AttestationRefusal::VerificationFailed);
        }
        if verification.evidence.is_empty() {
            return Err(AttestationRefusal::NoEvidence);
        }
        if verification.independence == IndependenceClass::SelfReported {
            return Err(AttestationRefusal::SelfCertified);
        }
        if &verification.verifier == subject_actor {
            return Err(AttestationRefusal::VerifierIsTheSubjectActor);
        }

        let statement = AttestationStatement {
            subject: verification.subject.clone(),
            verifier: verification.verifier.clone(),
            policy,
            runtime,
            adapter,
            delegation,
            evidence: verification.evidence.clone(),
        };
        let statement_digest = statement
            .digest()
            .map_err(|error| AttestationRefusal::Encoding(error.to_string()))?;
        Ok(Self {
            statement,
            statement_digest,
        })
    }

    /// The identities this attestation binds.
    pub fn statement(&self) -> &AttestationStatement {
        &self.statement
    }

    /// The digest over those identities.
    pub fn statement_digest(&self) -> &Digest {
        &self.statement_digest
    }

    /// Whether this attestation is about the given subject.
    ///
    /// The question a consumer should ask instead of reading `subject` and
    /// comparing, because it is the question that has a wrong answer worth
    /// preventing: an attestation presented for work it does not cover.
    pub fn covers(&self, subject: &Digest) -> bool {
        &self.statement.subject == subject
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            statement: AttestationStatement,
            statement_digest: Digest,
        }

        let wire = Wire::deserialize(deserializer)?;
        let recomputed = wire.statement.digest().map_err(serde::de::Error::custom)?;
        if recomputed != wire.statement_digest {
            return Err(serde::de::Error::custom(
                AttestationRefusal::StatementDigestMismatch,
            ));
        }
        Ok(Self {
            statement: wire.statement,
            statement_digest: wire.statement_digest,
        })
    }
}

/// Evidence-bearing completion of operational handoff and commissioner revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffReceipt {
    /// Institution whose operation was handed off.
    institution: InstitutionId,
    /// Preserved client-owned workspace.
    workspace: InstitutionWorkspaceId,
    /// Digest of the preserved workspace snapshot.
    workspace_digest: Digest,
    /// Commissioning record incorporated into the generation.
    commissioning_record: CommissioningRecordId,
    /// Digest of that exact commissioning record.
    commissioning_record_digest: Digest,
    /// Activated operational runtime generation.
    generation: RuntimeGenerationId,
    /// Commissioner whose temporary authority was revoked or expired.
    commissioner: PrincipalId,
    /// Revoked/expired commissioner delegation.
    revoked_delegation: DelegationId,
    /// Digest of the complete revoked commissioner grant.
    revoked_grant_digest: Digest,
    /// Evidence proving that commissioner authority was revoked or expired.
    revocation_evidence: EvidenceRecord,
    /// Client principal accepting custody and continuity responsibility.
    accepted_by: PrincipalId,
    /// Exact delegation carrying the accepting client's handoff authority.
    acceptance_delegation: DelegationId,
    /// Evidence that the operational generation remained functional afterward.
    continuity_evidence: Vec<EvidenceRecord>,
    /// Known unresolved obligations retained rather than narrated away.
    unresolved_obligations: BTreeSet<String>,
    /// Digest of the exact owner-approved obligation set.
    unresolved_obligations_digest: Digest,
}

/// A handoff claim was hollow or inconsistent with its resolved provenance.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandoffError {
    /// Workspace, commissioning record, or generation provenance disagreed.
    Provenance(RuntimeGenerationError),
    /// Post-revocation operational continuity had no evidence.
    MissingContinuityEvidence,
    /// One requested evidence identity was absent from trusted admission.
    EvidenceNotAdmitted,
    /// Revocation or continuity evidence was bound to another subject.
    EvidenceSubjectMismatch,
    /// Handoff evidence was not produced by the institution owner accepting custody.
    EvidenceProducerMismatch,
    /// Handoff evidence was produced under another owner delegation.
    EvidenceDelegationMismatch,
    /// The trusted grant store did not contain the exact ended commissioner grant.
    GrantStateMismatch,
    /// At least one commissioner grant remained active for the workspace.
    CommissionerAuthorityStillActive,
    /// Handoff evidence was not admitted as institution-owner authority evidence.
    EvidenceClassMismatch,
    /// Continuity was observed before commissioner revocation.
    ContinuityPrecedesRevocation,
    /// Handoff subject canonical encoding failed.
    Encoding(CanonicalError),
    /// Handoff did not bind an operational generation.
    NonOperationalGeneration,
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provenance(source) => {
                write!(formatter, "handoff provenance is invalid: {source}")
            }
            Self::MissingContinuityEvidence => {
                formatter.write_str("handoff lacks post-revocation continuity evidence")
            }
            Self::EvidenceNotAdmitted => {
                formatter.write_str("handoff evidence was not admitted by the trusted store")
            }
            Self::EvidenceSubjectMismatch => {
                formatter.write_str("handoff evidence names a different revocation or generation")
            }
            Self::EvidenceProducerMismatch => {
                formatter.write_str("handoff evidence was not produced by the workspace owner")
            }
            Self::EvidenceDelegationMismatch => {
                formatter.write_str("handoff evidence used the wrong owner delegation")
            }
            Self::GrantStateMismatch => {
                formatter.write_str("handoff grant state does not prove revocation or expiry")
            }
            Self::CommissionerAuthorityStillActive => {
                formatter.write_str("commissioner authority remains active after handoff")
            }
            Self::EvidenceClassMismatch => {
                formatter.write_str("handoff evidence lacks human-authority admission")
            }
            Self::ContinuityPrecedesRevocation => {
                formatter.write_str("continuity evidence predates commissioner revocation")
            }
            Self::Encoding(_) => formatter.write_str("handoff evidence subject cannot be encoded"),
            Self::NonOperationalGeneration => {
                formatter.write_str("handoff generation is not operational")
            }
        }
    }
}

impl std::error::Error for HandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provenance(source) => Some(source),
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}

impl HandoffReceipt {
    /// Validate and construct the completion record for client handoff.
    ///
    /// The receipt is intentionally not deserializable directly: untrusted wire
    /// input must first resolve the exact workspace, commissioning record, and
    /// runtime generation and then pass this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError`] when provenance axes disagree, the generation is
    /// not operational, or exact trusted revocation/continuity evidence is
    /// absent, mismatched, or temporally unordered.
    ///
    /// Time: O(e log e). Space: O(e), where e is continuity evidence count.
    #[expect(
        clippy::too_many_arguments,
        reason = "handoff binds seven independent authority, provenance, and evidence inputs"
    )]
    pub fn new(
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        generation: &RuntimeGeneration,
        trusted_grants: &TrustedCommissionerGrantRegistry,
        trusted_evidence: &TrustedEvidenceRegistry,
        revocation_evidence: &EvidenceId,
        continuity_evidence: &BTreeSet<EvidenceId>,
    ) -> Result<Self, HandoffError> {
        generation
            .resolve_provenance(workspace, commissioning)
            .map_err(HandoffError::Provenance)?;
        if generation.inputs().approved.lifecycle != LifecycleProfile::Operational {
            return Err(HandoffError::NonOperationalGeneration);
        }
        if continuity_evidence.is_empty() {
            return Err(HandoffError::MissingContinuityEvidence);
        }
        let revocation = trusted_evidence
            .resolve(revocation_evidence)
            .ok_or(HandoffError::EvidenceNotAdmitted)?;
        let expected_revocation = commissioner_revocation_subject_digest(
            &workspace.institution,
            &workspace.id,
            commissioning.id(),
            commissioning.commissioner_grant_digest(),
        )
        .map_err(HandoffError::Encoding)?;
        if revocation.subject != expected_revocation {
            return Err(HandoffError::EvidenceSubjectMismatch);
        }
        if revocation.producer != workspace.owner {
            return Err(HandoffError::EvidenceProducerMismatch);
        }
        if revocation.producer_delegation != workspace.owner_delegation {
            return Err(HandoffError::EvidenceDelegationMismatch);
        }
        if !matches!(&revocation.independence, IndependenceClass::HumanAuthority) {
            return Err(HandoffError::EvidenceClassMismatch);
        }
        let current_grant = trusted_grants
            .resolve(commissioning.commissioner_delegation())
            .ok_or(HandoffError::GrantStateMismatch)?;
        let current_grant_digest = current_grant.digest().map_err(HandoffError::Encoding)?;
        let authority_ended_at = current_grant.authority_ended_at();
        if current_grant_digest != *commissioning.commissioner_grant_digest()
            || trusted_grants.as_of() < revocation.observed_at
            || revocation.observed_at < authority_ended_at
            || authority_ended_at <= commissioning.captured_at()
        {
            return Err(HandoffError::GrantStateMismatch);
        }
        if trusted_grants.active_count_for(&workspace.institution, &workspace.id) != 0 {
            return Err(HandoffError::CommissionerAuthorityStillActive);
        }
        let all_authority_ended_at = trusted_grants
            .latest_authority_end_for(&workspace.institution, &workspace.id)
            .ok_or(HandoffError::GrantStateMismatch)?;
        let expected_continuity = operational_continuity_subject_digest(
            &workspace.institution,
            &workspace.id,
            generation.id(),
        )
        .map_err(HandoffError::Encoding)?;
        let continuity = continuity_evidence
            .iter()
            .map(|id| {
                trusted_evidence
                    .resolve(id)
                    .ok_or(HandoffError::EvidenceNotAdmitted)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if continuity
            .iter()
            .any(|record| record.subject != expected_continuity)
        {
            return Err(HandoffError::EvidenceSubjectMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.producer != workspace.owner)
        {
            return Err(HandoffError::EvidenceProducerMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.producer_delegation != workspace.owner_delegation)
        {
            return Err(HandoffError::EvidenceDelegationMismatch);
        }
        if continuity
            .iter()
            .any(|record| !matches!(&record.independence, IndependenceClass::HumanAuthority))
        {
            return Err(HandoffError::EvidenceClassMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at <= revocation.observed_at)
        {
            return Err(HandoffError::ContinuityPrecedesRevocation);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at <= all_authority_ended_at)
        {
            return Err(HandoffError::CommissionerAuthorityStillActive);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at > trusted_grants.as_of())
        {
            return Err(HandoffError::GrantStateMismatch);
        }
        Ok(Self {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            workspace_digest: commissioning.workspace_digest().clone(),
            commissioning_record: commissioning.id().clone(),
            commissioning_record_digest: generation.inputs().commissioning_record_digest.clone(),
            generation: generation.id().clone(),
            commissioner: commissioning.commissioner().clone(),
            revoked_delegation: commissioning.commissioner_delegation().clone(),
            revoked_grant_digest: commissioning.commissioner_grant_digest().clone(),
            revocation_evidence: revocation.clone(),
            accepted_by: workspace.owner.clone(),
            acceptance_delegation: workspace.owner_delegation.clone(),
            continuity_evidence: continuity.into_iter().cloned().collect(),
            unresolved_obligations: commissioning.unresolved_obligations().clone(),
            unresolved_obligations_digest: commissioning.unresolved_obligations_digest().clone(),
        })
    }
}

#[cfg(test)]
#[path = "tests/handoff.rs"]
mod commissioning_tests;

#[cfg(test)]
#[path = "tests/assessment.rs"]
mod assessment_tests;

#[cfg(test)]
#[path = "tests/assurance.rs"]
mod assurance_tests;

#[cfg(test)]
#[path = "tests/attestation.rs"]
mod attestation_tests;
