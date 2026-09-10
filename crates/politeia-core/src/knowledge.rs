//! Institutional knowledge: what was observed, what it is taken to mean, and
//! what has to be true before either becomes a fact.
//!
//! `docs/03-ONTOLOGY.md` separates three things that a system without types
//! runs together: an `Observation` is a sourced statement about reality, a
//! `CandidateClaim` is an interpreted proposition with confidence and
//! provenance, and an `ApprovedFact` is what the institution has accepted. The
//! interpretation step is where a source's word becomes the institution's, and
//! it is the step worth making visible.
//!
//! WHY contestedness is derived rather than declared: a `contested: bool` is a
//! field, and a field can be wrong or simply never set. Reading it off the
//! observations means a contradiction cannot be dropped by omission --
//! `docs/18-FIRST_VERTICAL_SLICE.md` requires that contradictions *remain
//! visible until approved*, and a claim that computes its own status is how
//! that survives someone forgetting.
//!
//! The same reasoning applies to support. A declared confidence is a number
//! nothing can contradict; [`Support`] is read off how many distinct sources
//! observed the thing, which is a fact about the evidence rather than about the
//! interpreter's mood.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_bytes;
use crate::{
    AdapterId, ClaimId, DelegationId, Digest, EvidenceId, InstitutionWorkspaceId, ObservationId,
    PrincipalId,
};
use crate::{
    evidence::TrustedEvidenceRegistry,
    institution::InstitutionWorkspace,
    trust::{AdmissionError, AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire},
};

/// A sourced statement about reality.
///
/// Every field answers "how do you know", and none of them is the statement's
/// meaning: an observation records that a named source, reached through an
/// exact adapter, said a particular thing at a particular time. What it is
/// taken to mean is a [`CandidateClaim`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    /// This observation's identity.
    pub id: ObservationId,
    /// The workspace that owns the observation.
    ///
    /// WHY an observation names its workspace: institutional facts are
    /// client-owned, and `docs/16-DATA_GOVERNANCE.md` requires an explicit
    /// authorized export before one institution's material is reused by
    /// another. Without this field a cross-institution observation is
    /// structurally indistinguishable from a local one, and the quarantine
    /// `docs/11-FAILURE_SEMANTICS.md` requires has nothing to key on.
    pub workspace: InstitutionWorkspaceId,
    /// The source the statement came from, as the institution names it.
    pub source: String,
    /// The exact adapter that reached the source.
    pub adapter: AdapterId,
    /// Digest of the subject the statement is about.
    pub subject: Digest,
    /// Digest of the statement itself.
    pub statement: Digest,
    /// Trusted time the observation was admitted.
    pub observed_at: Timestamp,
    /// The admitted evidence record backing it.
    pub evidence: EvidenceId,
}

impl crate::institution::WorkspaceScoped for Observation {
    fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }
}

/// Inert observation data received before installed-key and evidence checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationRequest {
    /// Stable identity retained across authenticated re-admission.
    pub id: ObservationId,
    /// The source the statement came from, as the institution names it.
    pub source: String,
    /// The exact adapter that reached the source.
    pub adapter: AdapterId,
    /// Digest of the subject the statement is about.
    pub subject: Digest,
    /// Digest of the statement itself.
    pub statement: Digest,
    /// Time the source was observed.
    pub observed_at: Timestamp,
    /// Evidence that establishes the source observation.
    pub evidence: EvidenceId,
}

/// Exact source observations admitted for one workspace.
#[derive(Clone, Debug, Default)]
pub struct TrustedObservationRegistry {
    workspace: Option<InstitutionWorkspaceId>,
    observations: BTreeMap<ObservationId, Observation>,
}

impl TrustedObservationRegistry {
    /// Admit signed observations after resolving their evidence from trusted admission.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationAdmissionRefusal`] when the signature is invalid,
    /// the evidence is absent or rebound, or the evidence producer did not
    /// sign the observation.
    pub fn admit_signed(
        workspace: &InstitutionWorkspace,
        anchors: &InstitutionTrustAnchors,
        evidence: &TrustedEvidenceRegistry,
        statements: impl IntoIterator<Item = SignedAdmissionWire<ObservationRequest>>,
    ) -> Result<Self, ObservationAdmissionRefusal> {
        if anchors.institution() != &workspace.institution || anchors.workspace() != &workspace.id {
            return Err(ObservationAdmissionRefusal::ForeignTrustScope);
        }
        if evidence.institution() != Some(&workspace.institution)
            || evidence.workspace() != Some(&workspace.id)
        {
            return Err(ObservationAdmissionRefusal::ForeignEvidenceScope);
        }
        let mut observations = BTreeMap::new();
        for statement in statements {
            let admitted = anchors
                .admit_expected(AdmissionKind::Observation, statement)
                .map_err(ObservationAdmissionRefusal::Authentication)?;
            let request = admitted.payload();
            let record = evidence
                .resolve(&request.evidence)
                .ok_or(ObservationAdmissionRefusal::EvidenceNotAdmitted)?;
            if record.subject != request.subject {
                return Err(ObservationAdmissionRefusal::EvidenceSubjectMismatch);
            }
            if record.producer != *admitted.signer() {
                return Err(ObservationAdmissionRefusal::EvidenceProducerMismatch);
            }
            if record.observed_at != request.observed_at {
                return Err(ObservationAdmissionRefusal::EvidenceTimeMismatch);
            }
            let expected_payload = observation_evidence_payload_digest(&workspace.id, request)
                .map_err(ObservationAdmissionRefusal::Encoding)?;
            if record.payload_digest != expected_payload {
                return Err(ObservationAdmissionRefusal::EvidencePayloadMismatch);
            }
            let observation = Observation {
                id: request.id.clone(),
                workspace: workspace.id.clone(),
                source: request.source.clone(),
                adapter: request.adapter.clone(),
                subject: request.subject.clone(),
                statement: request.statement.clone(),
                observed_at: request.observed_at,
                evidence: request.evidence.clone(),
            };
            if observations
                .insert(observation.id.clone(), observation)
                .is_some()
            {
                return Err(ObservationAdmissionRefusal::DuplicateIdentity);
            }
        }
        Ok(Self {
            workspace: Some(workspace.id.clone()),
            observations,
        })
    }

    /// Construct a registry from an already-admitted trusted snapshot.
    ///
    /// This is a bootstrap boundary for persisted, previously verified
    /// observations. New received observations must use [`Self::admit_signed`].
    ///
    /// # Errors
    ///
    /// Returns [`ObservationAdmissionRefusal`] when an observation belongs to
    /// another workspace, has no trusted evidence, rebinds evidence to another
    /// subject, or repeats an identity.
    pub fn from_trusted_bootstrap(
        workspace: &InstitutionWorkspaceId,
        evidence: &TrustedEvidenceRegistry,
        observations: impl IntoIterator<Item = Observation>,
    ) -> Result<Self, ObservationAdmissionRefusal> {
        let mut registered = BTreeMap::new();
        for observation in observations {
            if observation.workspace != *workspace {
                return Err(ObservationAdmissionRefusal::ForeignWorkspace);
            }
            let record = evidence
                .resolve(&observation.evidence)
                .ok_or(ObservationAdmissionRefusal::EvidenceNotAdmitted)?;
            if record.subject != observation.subject {
                return Err(ObservationAdmissionRefusal::EvidenceSubjectMismatch);
            }
            if registered
                .insert(observation.id.clone(), observation)
                .is_some()
            {
                return Err(ObservationAdmissionRefusal::DuplicateIdentity);
            }
        }
        Ok(Self {
            workspace: Some(workspace.clone()),
            observations: registered,
        })
    }

    fn resolve(&self, id: &ObservationId) -> Option<&Observation> {
        self.observations.get(id)
    }

    fn workspace(&self) -> Option<&InstitutionWorkspaceId> {
        self.workspace.as_ref()
    }
}

/// Why an observation did not enter a trusted registry.
#[derive(Debug)]
#[non_exhaustive]
pub enum ObservationAdmissionRefusal {
    /// The installed anchors do not belong to the requested workspace.
    ForeignTrustScope,
    /// Signature or installed-signer checks failed.
    Authentication(AdmissionError),
    /// The cited evidence identity was absent from trusted admission.
    EvidenceNotAdmitted,
    /// The cited evidence concerns another subject.
    EvidenceSubjectMismatch,
    /// The admitted signer differs from the evidence producer.
    EvidenceProducerMismatch,
    /// Evidence came from another institution or workspace admission scope.
    ForeignEvidenceScope,
    /// Evidence payload bytes do not bind this exact observation statement.
    EvidencePayloadMismatch,
    /// Evidence metadata records another observation time.
    EvidenceTimeMismatch,
    /// The observation/evidence binding could not be encoded canonically.
    Encoding(crate::canonical::CanonicalError),
    /// Bootstrap supplied an observation for another workspace.
    ForeignWorkspace,
    /// One snapshot repeated an observation identity.
    DuplicateIdentity,
}

impl std::fmt::Display for ObservationAdmissionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignTrustScope => {
                formatter.write_str("installed anchors do not match observation workspace")
            }
            Self::Authentication(error) => {
                write!(formatter, "observation authentication failed: {error}")
            }
            Self::EvidenceNotAdmitted => {
                formatter.write_str("observation evidence was not admitted")
            }
            Self::EvidenceSubjectMismatch => {
                formatter.write_str("observation evidence concerns another subject")
            }
            Self::EvidenceProducerMismatch => {
                formatter.write_str("observation signer differs from evidence producer")
            }
            Self::ForeignEvidenceScope => {
                formatter.write_str("observation evidence belongs to another trust scope")
            }
            Self::EvidencePayloadMismatch => {
                formatter.write_str("evidence payload does not bind the exact observation")
            }
            Self::EvidenceTimeMismatch => {
                formatter.write_str("evidence metadata records another observation time")
            }
            Self::Encoding(error) => {
                write!(
                    formatter,
                    "observation evidence binding cannot encode: {error}"
                )
            }
            Self::ForeignWorkspace => {
                formatter.write_str("observation belongs to another workspace")
            }
            Self::DuplicateIdentity => {
                formatter.write_str("observation registry repeats an identity")
            }
        }
    }
}

impl std::error::Error for ObservationAdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct ObservationEvidencePayload<'a> {
    kind: &'static str,
    workspace: &'a InstitutionWorkspaceId,
    source: &'a str,
    adapter: &'a AdapterId,
    subject: &'a Digest,
    statement: &'a Digest,
    observed_at: Timestamp,
}

fn observation_evidence_payload_digest(
    workspace: &InstitutionWorkspaceId,
    request: &ObservationRequest,
) -> Result<Digest, crate::canonical::CanonicalError> {
    to_canonical_bytes(&ObservationEvidencePayload {
        kind: "observation_evidence_payload_v1",
        workspace,
        source: &request.source,
        adapter: &request.adapter,
        subject: &request.subject,
        statement: &request.statement,
        observed_at: request.observed_at,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// How well-supported a claim is, read off its observations.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Nothing observed it.
    None,
    /// One source observed it.
    Single,
    /// Two or more distinct sources observed it.
    ///
    /// Counted by source rather than by observation: one source polled twice
    /// has said one thing twice, and treating that as corroboration is how a
    /// single unreliable source becomes a consensus.
    Corroborated,
}

/// Where a claim stands before anyone approves it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// No observation supports it.
    Unsupported,
    /// At least one observation contradicts it.
    ///
    /// Contradiction outranks support: a claim with nine supporting
    /// observations and one contradicting one is contested, not
    /// nine-tenths true.
    Contested,
    /// Supported, uncontradicted, and not yet approved.
    Candidate,
}

/// An interpreted proposition, with the observations behind and against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaim {
    /// This claim's identity.
    pub id: ClaimId,
    /// Institution workspace in which this claim may be evaluated.
    pub workspace: InstitutionWorkspaceId,
    /// Digest of the subject the proposition is about.
    pub subject: Digest,
    /// Digest of the proposition.
    pub proposition: Digest,
    /// Observations that support it, by the source that made each.
    pub supported_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Observations that contradict it, by the source that made each.
    pub contradicted_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Axes the reconnaissance that produced this claim did not cover.
    ///
    /// Declared by the interpreter, because only it knows what it did not look
    /// at. An empty set is a claim that nothing was missed, which is a
    /// statement rather than a default -- and one an approver has to accept.
    pub missed_axes: BTreeSet<String>,
    /// The principal that interpreted the observations.
    pub interpreter: PrincipalId,
    /// The exact delegation it interpreted under.
    pub interpreter_delegation: DelegationId,
}

impl CandidateClaim {
    /// How well-supported the claim is.
    pub fn support(&self) -> Support {
        match self.supported_by.len() {
            0 => Support::None,
            1 => Support::Single,
            _ => Support::Corroborated,
        }
    }

    /// Where the claim stands.
    pub fn status(&self) -> ClaimStatus {
        if !self.contradicted_by.is_empty() {
            ClaimStatus::Contested
        } else if self.supported_by.is_empty() {
            ClaimStatus::Unsupported
        } else {
            ClaimStatus::Candidate
        }
    }
}

/// An institution owner's acceptance of one claim.
///
/// It restates what it is accepting rather than pointing at it. That is
/// deliberate: an approval that carried only a claim identity would still be
/// valid after the claim gained a contradiction, and the approver would have
/// accepted something they never saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactApprovalRequest {
    /// The claim being accepted.
    pub claim: ClaimId,
    /// The subject as the approver saw it.
    pub subject: Digest,
    /// The proposition as the approver saw it.
    pub proposition: Digest,
    /// The status the approver saw.
    pub acknowledged_status: ClaimStatus,
    /// The gaps the approver saw and accepted.
    pub acknowledged_missed_axes: BTreeSet<String>,
    /// When the approval was given.
    pub approved_at: Timestamp,
}

/// Why a claim did not become an approved fact.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApprovalRefusal {
    /// Installed signing-key verification failed.
    Authentication(AdmissionError),
    /// The candidate or its observations belongs to another workspace.
    ForeignWorkspace,
    /// The installed anchors belong to another institution or workspace.
    ForeignTrustScope,
    /// The signed approver is not the workspace's installed owner.
    NotInstitutionOwner,
    /// The approval names a different claim.
    WrongClaim {
        /// The claim presented.
        claim: ClaimId,
        /// The claim the approval names.
        approved: ClaimId,
    },
    /// The proposition changed after the approval was given.
    PropositionChanged,
    /// The subject changed after the approval was signed.
    SubjectChanged,
    /// The claim is contradicted and no owner may approve it as it stands.
    ///
    /// The contradiction has to be resolved -- by evidence, by a correction, or
    /// by withdrawing the claim -- rather than approved past.
    /// `docs/18-FIRST_VERTICAL_SLICE.md`: contradictions remain visible until
    /// approved, and this is what "remain visible" means when someone tries to
    /// approve anyway.
    Contested {
        /// The sources that contradict it.
        sources: BTreeSet<String>,
    },
    /// Nothing observed the claim.
    Unsupported,
    /// A claimed support or contradiction reference was not admitted.
    ObservationNotAdmitted {
        /// Missing observation identity.
        id: ObservationId,
    },
    /// A claim labeled an observation under a different source.
    ObservationSourceMismatch {
        /// Observation identity.
        id: ObservationId,
    },
    /// A claim referenced an observation about another subject.
    ObservationSubjectMismatch {
        /// Observation identity.
        id: ObservationId,
    },
    /// The approver saw a different status than the claim now has.
    StatusChanged {
        /// What the approver acknowledged.
        acknowledged: ClaimStatus,
        /// What the claim is now.
        actual: ClaimStatus,
    },
    /// The claim declares gaps the approval does not acknowledge.
    UnacknowledgedGaps {
        /// The axes declared and not acknowledged.
        missed: BTreeSet<String>,
    },
}

impl std::fmt::Display for ApprovalRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalRefusal::Authentication(error) => {
                write!(formatter, "approval authentication failed: {error}")
            }
            ApprovalRefusal::ForeignWorkspace => {
                formatter.write_str("claim or observation belongs to another workspace")
            }
            ApprovalRefusal::ForeignTrustScope => {
                formatter.write_str("installed anchors do not match approval workspace")
            }
            ApprovalRefusal::NotInstitutionOwner => {
                formatter.write_str("signed approver is not the workspace owner")
            }
            ApprovalRefusal::WrongClaim { claim, approved } => write!(
                formatter,
                "approval names {approved:?}, not the claim {claim:?} presented"
            ),
            ApprovalRefusal::PropositionChanged => {
                formatter.write_str("the proposition changed after the approval was given")
            }
            ApprovalRefusal::SubjectChanged => {
                formatter.write_str("the subject changed after the approval was given")
            }
            ApprovalRefusal::Contested { sources } => write!(
                formatter,
                "the claim is contradicted by {sources:?} and cannot be approved as it stands"
            ),
            ApprovalRefusal::Unsupported => {
                formatter.write_str("no observation supports the claim")
            }
            ApprovalRefusal::ObservationNotAdmitted { id } => {
                write!(formatter, "claim observation {id:?} was not admitted")
            }
            ApprovalRefusal::ObservationSourceMismatch { id } => write!(
                formatter,
                "claim source label disagrees with observation {id:?}"
            ),
            ApprovalRefusal::ObservationSubjectMismatch { id } => write!(
                formatter,
                "claim observation {id:?} concerns another subject"
            ),
            ApprovalRefusal::StatusChanged {
                acknowledged,
                actual,
            } => write!(
                formatter,
                "the approver saw {acknowledged:?}; the claim is now {actual:?}"
            ),
            ApprovalRefusal::UnacknowledgedGaps { missed } => write!(
                formatter,
                "the claim declares gaps the approval does not acknowledge: {missed:?}"
            ),
        }
    }
}

impl std::error::Error for ApprovalRefusal {}

/// A claim the institution has accepted.
///
/// Constructible only through [`approve_claim`], so authentication, ownership,
/// and evidence-resolution checks are not something a caller can route around
/// by building the value directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApprovedFact {
    claim: ClaimId,
    workspace: InstitutionWorkspaceId,
    subject: Digest,
    proposition: Digest,
    support: Support,
    accepted_gaps: BTreeSet<String>,
    owner: PrincipalId,
    owner_delegation: DelegationId,
    approved_at: Timestamp,
}

impl ApprovedFact {
    /// The claim this fact came from.
    pub fn claim(&self) -> &ClaimId {
        &self.claim
    }
    /// The institution workspace that accepted the fact.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }
    /// The subject the fact is about.
    pub fn subject(&self) -> &Digest {
        &self.subject
    }
    /// The proposition accepted.
    pub fn proposition(&self) -> &Digest {
        &self.proposition
    }
    /// How well-supported it was when accepted.
    pub fn support(&self) -> Support {
        self.support
    }
    /// The gaps the owner accepted along with it.
    ///
    /// Carried forward rather than discarded: a fact approved with known gaps
    /// is a different thing from one approved without, and a consumer that
    /// cannot tell them apart will treat them alike.
    pub fn accepted_gaps(&self) -> &BTreeSet<String> {
        &self.accepted_gaps
    }
    /// The institution owner that accepted it.
    pub fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    /// The workspace delegation that establishes the owner's authority.
    pub fn owner_delegation(&self) -> &DelegationId {
        &self.owner_delegation
    }
    /// When it was accepted.
    pub fn approved_at(&self) -> Timestamp {
        self.approved_at
    }
}

/// Accept an evidence-resolved claim as an institutional fact.
///
/// The signed request is raw transport input. This function authenticates it
/// against installed anchors for the exact workspace, requires that signer to
/// be the workspace owner, and resolves every cited observation from trusted
/// admission before it can produce an [`ApprovedFact`].
///
/// # Errors
///
/// Returns [`ApprovalRefusal`] when the approval does not match the claim it
/// names, when the claim is contested or unsupported, when its status has moved
/// since the approver saw it, or when it declares gaps the approval does not
/// acknowledge.
///
/// Time: O(g) for g declared gaps. Space: O(g).
pub fn approve_claim(
    workspace: &InstitutionWorkspace,
    observations: &TrustedObservationRegistry,
    anchors: &InstitutionTrustAnchors,
    claim: &CandidateClaim,
    approval: SignedAdmissionWire<FactApprovalRequest>,
) -> Result<ApprovedFact, ApprovalRefusal> {
    if anchors.institution() != &workspace.institution || anchors.workspace() != &workspace.id {
        return Err(ApprovalRefusal::ForeignTrustScope);
    }
    if claim.workspace != workspace.id || observations.workspace() != Some(&workspace.id) {
        return Err(ApprovalRefusal::ForeignWorkspace);
    }
    validate_claim_observations(claim, observations)?;

    let admitted = anchors
        .admit_expected(AdmissionKind::FactApproval, approval)
        .map_err(ApprovalRefusal::Authentication)?;
    if admitted.signer() != &workspace.owner {
        return Err(ApprovalRefusal::NotInstitutionOwner);
    }
    let approval = admitted.payload();
    if approval.claim != claim.id {
        return Err(ApprovalRefusal::WrongClaim {
            claim: claim.id.clone(),
            approved: approval.claim.clone(),
        });
    }
    if approval.subject != claim.subject {
        return Err(ApprovalRefusal::SubjectChanged);
    }
    if approval.proposition != claim.proposition {
        return Err(ApprovalRefusal::PropositionChanged);
    }

    let status = claim.status();
    if approval.acknowledged_status != status {
        return Err(ApprovalRefusal::StatusChanged {
            acknowledged: approval.acknowledged_status,
            actual: status,
        });
    }
    match status {
        ClaimStatus::Contested => {
            return Err(ApprovalRefusal::Contested {
                sources: claim.contradicted_by.keys().cloned().collect(),
            });
        }
        ClaimStatus::Unsupported => return Err(ApprovalRefusal::Unsupported),
        ClaimStatus::Candidate => {}
    }

    // Set difference rather than equality: acknowledging a gap the claim does
    // not declare is harmless caution, while failing to acknowledge one it does
    // declare is the approver not having seen it.
    let unacknowledged: BTreeSet<String> = claim
        .missed_axes
        .difference(&approval.acknowledged_missed_axes)
        .cloned()
        .collect();
    if !unacknowledged.is_empty() {
        return Err(ApprovalRefusal::UnacknowledgedGaps {
            missed: unacknowledged,
        });
    }

    Ok(ApprovedFact {
        claim: claim.id.clone(),
        workspace: workspace.id.clone(),
        subject: claim.subject.clone(),
        proposition: claim.proposition.clone(),
        support: claim.support(),
        accepted_gaps: claim.missed_axes.clone(),
        owner: admitted.signer().clone(),
        owner_delegation: workspace.owner_delegation.clone(),
        approved_at: approval.approved_at,
    })
}

fn validate_claim_observations(
    claim: &CandidateClaim,
    observations: &TrustedObservationRegistry,
) -> Result<(), ApprovalRefusal> {
    for sources in [&claim.supported_by, &claim.contradicted_by] {
        for (source, identities) in sources {
            for id in identities {
                let observation = observations
                    .resolve(id)
                    .ok_or_else(|| ApprovalRefusal::ObservationNotAdmitted { id: id.clone() })?;
                if observation.source != *source {
                    return Err(ApprovalRefusal::ObservationSourceMismatch { id: id.clone() });
                }
                if observation.subject != claim.subject {
                    return Err(ApprovalRefusal::ObservationSubjectMismatch { id: id.clone() });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "fixture construction must fail loudly when its authenticated boundary drifts"
    )]

    use super::*;

    use ed25519_dalek::SigningKey;

    use crate::evidence::{EvidenceRecord, EvidenceRequest, IndependenceClass};
    use crate::test_support::fixture;
    use crate::trust::TrustedSigningKey;

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    fn subject() -> Digest {
        Digest::blake3(b"the institution's billing contact")
    }

    fn proposition() -> Digest {
        Digest::blake3(b"billing is handled by the finance team")
    }

    struct Fixture {
        workspace: InstitutionWorkspace,
        owner_key: SigningKey,
        owner: PrincipalId,
        observation: Observation,
        registry: TrustedObservationRegistry,
        anchors: InstitutionTrustAnchors,
    }

    #[expect(
        clippy::expect_used,
        reason = "the canonical workspace fixture must be internally coherent"
    )]
    fn fixture_with_observation() -> Fixture {
        let base = fixture();
        let owner_key = SigningKey::from_bytes(&[23; 32]);
        let owner = base.workspace.owner.clone();
        let evidence_id = EvidenceId::new();
        let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap([EvidenceRecord {
            id: evidence_id.clone(),
            subject: subject(),
            producer: owner.clone(),
            producer_delegation: base.workspace.owner_delegation.clone(),
            method: "fixture".to_string(),
            payload_digest: Digest::blake3(b"evidence"),
            observed_at: now(),
            independence: IndependenceClass::HumanAuthority,
        }])
        .expect("fixture evidence identity is unique");
        let observation = Observation {
            id: ObservationId::new(),
            workspace: base.workspace.id.clone(),
            source: "crm".to_string(),
            adapter: AdapterId::new(),
            subject: subject(),
            statement: Digest::blake3(b"finance handles billing"),
            observed_at: now(),
            evidence: evidence_id,
        };
        let registry = TrustedObservationRegistry::from_trusted_bootstrap(
            &base.workspace.id,
            &evidence,
            [observation.clone()],
        )
        .expect("fixture observation is evidence-bound");
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            base.workspace.institution.clone(),
            base.workspace.id.clone(),
            [TrustedSigningKey::new(
                owner.clone(),
                owner_key.verifying_key().to_bytes(),
                BTreeSet::from([AdmissionKind::FactApproval]),
            )
            .expect("fixture key is valid")],
        )
        .expect("fixture owner is unique");
        Fixture {
            workspace: base.workspace,
            owner_key,
            owner,
            observation,
            registry,
            anchors,
        }
    }

    fn claim(fixture: &Fixture, contradicted: bool) -> CandidateClaim {
        CandidateClaim {
            id: ClaimId::new(),
            workspace: fixture.workspace.id.clone(),
            subject: subject(),
            proposition: proposition(),
            supported_by: BTreeMap::from([(
                fixture.observation.source.clone(),
                BTreeSet::from([fixture.observation.id.clone()]),
            )]),
            contradicted_by: if contradicted {
                BTreeMap::from([(
                    fixture.observation.source.clone(),
                    BTreeSet::from([fixture.observation.id.clone()]),
                )])
            } else {
                BTreeMap::new()
            },
            missed_axes: BTreeSet::from(["subsidiaries".to_string()]),
            interpreter: PrincipalId::new(),
            interpreter_delegation: DelegationId::new(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a signed fixture approval must encode canonically"
    )]
    fn approval(
        fixture: &Fixture,
        claim: &CandidateClaim,
        signer: PrincipalId,
        key: &SigningKey,
    ) -> SignedAdmissionWire<FactApprovalRequest> {
        SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            signer,
            FactApprovalRequest {
                claim: claim.id.clone(),
                subject: claim.subject.clone(),
                proposition: claim.proposition.clone(),
                acknowledged_status: claim.status(),
                acknowledged_missed_axes: claim.missed_axes.clone(),
                approved_at: now(),
            },
            key,
        )
        .expect("fixture approval encodes")
    }

    #[test]
    fn authenticated_owner_approval_resolves_admitted_evidence() {
        let fixture = fixture_with_observation();
        let candidate = claim(&fixture, false);
        let fact = approve_claim(
            &fixture.workspace,
            &fixture.registry,
            &fixture.anchors,
            &candidate,
            approval(
                &fixture,
                &candidate,
                fixture.owner.clone(),
                &fixture.owner_key,
            ),
        )
        .expect("evidence-resolved owner approval succeeds");

        assert_eq!(fact.workspace(), &fixture.workspace.id);
        assert_eq!(fact.owner(), &fixture.owner);
        assert_eq!(fact.owner_delegation(), &fixture.workspace.owner_delegation);
        assert_eq!(
            fact.accepted_gaps(),
            &BTreeSet::from(["subsidiaries".to_string()])
        );
    }

    #[test]
    fn a_raw_or_wrongly_signed_approval_cannot_create_a_fact() {
        let fixture = fixture_with_observation();
        let candidate = claim(&fixture, false);
        let imposter = PrincipalId::new();
        let imposter_key = SigningKey::from_bytes(&[31; 32]);
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidate,
                approval(&fixture, &candidate, imposter, &imposter_key),
            ),
            Err(ApprovalRefusal::Authentication(
                AdmissionError::UnknownSigner
            ))
        ));
    }

    #[test]
    fn a_cross_workspace_signed_approval_is_refused() {
        let fixture = fixture_with_observation();
        let candidate = claim(&fixture, false);
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            fixture.workspace.institution.clone(),
            InstitutionWorkspaceId::new(),
            fixture.owner.clone(),
            FactApprovalRequest {
                claim: candidate.id.clone(),
                subject: candidate.subject.clone(),
                proposition: candidate.proposition.clone(),
                acknowledged_status: candidate.status(),
                acknowledged_missed_axes: candidate.missed_axes.clone(),
                approved_at: now(),
            },
            &fixture.owner_key,
        )
        .expect("fixture approval encodes");
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidate,
                wire
            ),
            Err(ApprovalRefusal::Authentication(
                AdmissionError::ForeignWorkspace
            ))
        ));
    }

    #[test]
    fn an_approval_of_a_stale_subject_is_refused() {
        let fixture = fixture_with_observation();
        let candidate = claim(&fixture, false);
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            fixture.owner.clone(),
            FactApprovalRequest {
                claim: candidate.id.clone(),
                subject: Digest::blake3(b"a later subject"),
                proposition: candidate.proposition.clone(),
                acknowledged_status: candidate.status(),
                acknowledged_missed_axes: candidate.missed_axes.clone(),
                approved_at: now(),
            },
            &fixture.owner_key,
        )
        .expect("fixture approval encodes");
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidate,
                wire
            ),
            Err(ApprovalRefusal::SubjectChanged)
        ));
    }

    #[test]
    fn evidence_cannot_be_rebound_to_another_observation_subject() {
        let fixture = fixture_with_observation();
        let record = EvidenceRecord {
            id: EvidenceId::new(),
            subject: Digest::blake3(b"another subject"),
            producer: fixture.owner.clone(),
            producer_delegation: fixture.workspace.owner_delegation.clone(),
            method: "fixture".to_string(),
            payload_digest: Digest::blake3(b"evidence"),
            observed_at: now(),
            independence: IndependenceClass::HumanAuthority,
        };
        let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap([record.clone()])
            .expect("fixture evidence identity is unique");
        let forged = Observation {
            id: ObservationId::new(),
            workspace: fixture.workspace.id.clone(),
            source: "crm".to_string(),
            adapter: AdapterId::new(),
            subject: subject(),
            statement: Digest::blake3(b"forged binding"),
            observed_at: now(),
            evidence: record.id,
        };
        assert!(matches!(
            TrustedObservationRegistry::from_trusted_bootstrap(
                &fixture.workspace.id,
                &evidence,
                [forged],
            ),
            Err(ObservationAdmissionRefusal::EvidenceSubjectMismatch)
        ));
    }

    #[test]
    fn observation_admission_binds_the_signed_producer_to_its_evidence() {
        let fixture = fixture_with_observation();
        let second = PrincipalId::new();
        let second_key = SigningKey::from_bytes(&[47; 32]);
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            [
                TrustedSigningKey::new(
                    fixture.owner.clone(),
                    fixture.owner_key.verifying_key().to_bytes(),
                    BTreeSet::from([AdmissionKind::Evidence, AdmissionKind::Observation]),
                )
                .expect("fixture key is valid"),
                TrustedSigningKey::new(
                    second.clone(),
                    second_key.verifying_key().to_bytes(),
                    BTreeSet::from([AdmissionKind::Observation]),
                )
                .expect("fixture key is valid"),
            ],
        )
        .expect("fixture principals are distinct");
        let request = ObservationRequest {
            id: ObservationId::new(),
            source: "crm".to_string(),
            adapter: AdapterId::new(),
            subject: subject(),
            statement: Digest::blake3(b"billing"),
            observed_at: now(),
            evidence: EvidenceId::new(),
        };
        let evidence = TrustedEvidenceRegistry::admit_signed(
            &anchors,
            [SignedAdmissionWire::sign(
                AdmissionKind::Evidence,
                fixture.workspace.institution.clone(),
                fixture.workspace.id.clone(),
                fixture.owner.clone(),
                EvidenceRequest {
                    id: request.evidence.clone(),
                    subject: request.subject.clone(),
                    producer_delegation: fixture.workspace.owner_delegation.clone(),
                    method: "fixture".to_string(),
                    payload_digest: observation_evidence_payload_digest(
                        &fixture.workspace.id,
                        &request,
                    )
                    .expect("fixture observation binding encodes"),
                    observed_at: request.observed_at,
                    independence: IndependenceClass::HumanAuthority,
                },
                &fixture.owner_key,
            )
            .expect("fixture evidence encodes")],
        )
        .expect("fixture evidence is admitted");
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::Observation,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            second,
            request,
            &second_key,
        )
        .expect("fixture observation encodes");
        assert!(matches!(
            TrustedObservationRegistry::admit_signed(
                &fixture.workspace,
                &anchors,
                &evidence,
                [wire],
            ),
            Err(ObservationAdmissionRefusal::EvidenceProducerMismatch)
        ));
    }

    #[test]
    fn signed_observation_re_admission_preserves_its_identity_and_exact_binding() {
        let fixture = fixture_with_observation();
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            [TrustedSigningKey::new(
                fixture.owner.clone(),
                fixture.owner_key.verifying_key().to_bytes(),
                BTreeSet::from([AdmissionKind::Evidence, AdmissionKind::Observation]),
            )
            .expect("fixture key is valid")],
        )
        .expect("fixture principal is unique");
        let request = ObservationRequest {
            id: ObservationId::new(),
            source: "crm".to_string(),
            adapter: AdapterId::new(),
            subject: subject(),
            statement: Digest::blake3(b"billing"),
            observed_at: now(),
            evidence: EvidenceId::new(),
        };
        let evidence = TrustedEvidenceRegistry::admit_signed(
            &anchors,
            [SignedAdmissionWire::sign(
                AdmissionKind::Evidence,
                fixture.workspace.institution.clone(),
                fixture.workspace.id.clone(),
                fixture.owner.clone(),
                EvidenceRequest {
                    id: request.evidence.clone(),
                    subject: request.subject.clone(),
                    producer_delegation: fixture.workspace.owner_delegation.clone(),
                    method: "fixture".to_string(),
                    payload_digest: observation_evidence_payload_digest(
                        &fixture.workspace.id,
                        &request,
                    )
                    .expect("fixture observation binding encodes"),
                    observed_at: request.observed_at,
                    independence: IndependenceClass::HumanAuthority,
                },
                &fixture.owner_key,
            )
            .expect("fixture evidence encodes")],
        )
        .expect("fixture evidence is admitted");
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::Observation,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            fixture.owner.clone(),
            request.clone(),
            &fixture.owner_key,
        )
        .expect("fixture observation encodes");
        let first = TrustedObservationRegistry::admit_signed(
            &fixture.workspace,
            &anchors,
            &evidence,
            [wire.clone()],
        )
        .expect("exact signed observation is admitted");
        let reloaded = TrustedObservationRegistry::admit_signed(
            &fixture.workspace,
            &anchors,
            &evidence,
            [wire],
        )
        .expect("same signed observation re-admits with its persisted identity");
        assert_eq!(first.resolve(&request.id), reloaded.resolve(&request.id));

        let mut mismatched = request;
        mismatched.source = "ledger".to_string();
        let mismatched = SignedAdmissionWire::sign(
            AdmissionKind::Observation,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            fixture.owner.clone(),
            mismatched,
            &fixture.owner_key,
        )
        .expect("fixture mismatched observation encodes");
        assert!(matches!(
            TrustedObservationRegistry::admit_signed(
                &fixture.workspace,
                &anchors,
                &evidence,
                [mismatched],
            ),
            Err(ObservationAdmissionRefusal::EvidencePayloadMismatch)
        ));
    }

    #[test]
    fn an_explicit_conflict_remains_unapprovable() {
        let fixture = fixture_with_observation();
        let candidate = claim(&fixture, true);
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidate,
                approval(
                    &fixture,
                    &candidate,
                    fixture.owner.clone(),
                    &fixture.owner_key
                ),
            ),
            Err(ApprovalRefusal::Contested { .. })
        ));
    }

    #[test]
    fn an_empty_or_fabricated_support_map_cannot_be_approved() {
        let fixture = fixture_with_observation();
        let mut candidate = claim(&fixture, false);
        candidate.supported_by = BTreeMap::new();
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidate,
                approval(
                    &fixture,
                    &candidate,
                    fixture.owner.clone(),
                    &fixture.owner_key
                ),
            ),
            Err(ApprovalRefusal::Unsupported)
        ));

        let mut fabricated = claim(&fixture, false);
        fabricated.supported_by =
            BTreeMap::from([("ledger".to_string(), BTreeSet::from([ObservationId::new()]))]);
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &fabricated,
                approval(
                    &fixture,
                    &fabricated,
                    fixture.owner.clone(),
                    &fixture.owner_key
                ),
            ),
            Err(ApprovalRefusal::ObservationNotAdmitted { .. })
        ));
    }
}
