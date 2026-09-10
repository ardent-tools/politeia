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
    AdapterId, ClaimId, DelegationId, Digest, EvidenceId, InstitutionId, InstitutionWorkspaceId,
    ObservationId, PrincipalId, SourceCaptureId,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Observation {
    /// This observation's identity.
    pub id: ObservationId,
    /// Exact descriptor-bounded capture from which this observation was admitted.
    pub capture: SourceCaptureId,
    /// Digest of the exact bounded manifest captured before this observation.
    pub capture_manifest_digest: Digest,
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
    /// Exact descriptor-bounded source capture the observation derives from.
    pub capture: SourceCaptureId,
    /// Digest of the exact capture content manifest the observer saw.
    pub capture_manifest_digest: Digest,
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

/// Inert signed-capture payload before installed-key admission.
///
/// The manifest is a sorted, duplicate-free explicit selection. It describes
/// exactly the relative members the source adapter was allowed to capture;
/// omission is never interpreted as a wildcard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceCaptureRequest {
    /// Stable capture identity retained across re-admission.
    pub id: SourceCaptureId,
    /// Institution-named external source.
    pub source: String,
    /// Adapter that read the descriptor-bounded source.
    pub adapter: AdapterId,
    /// Subject the source snapshot concerns.
    pub subject: Digest,
    /// Statement digest read from the source snapshot.
    pub statement: Digest,
    /// Source observation time.
    pub observed_at: Timestamp,
    /// Bounded reconnaissance delegation under which capture happened.
    pub reconnaissance_delegation: DelegationId,
    /// Exact read-only scope checked before this source was accessed.
    pub reconnaissance: crate::reconnaissance::ReconnaissanceScope,
    /// Explicit relative members selected by the capture descriptor.
    pub manifest: BTreeSet<String>,
    /// Digest of the descriptor that authorized this exact capture selection.
    pub descriptor_digest: Digest,
    /// Digest of exact bytes/content identities of the selected members.
    pub content_manifest_digest: Digest,
}

/// One authenticated descriptor-bounded source capture.
#[derive(Clone, Debug)]
pub struct SourceCapture {
    request: SourceCaptureRequest,
    signer: PrincipalId,
}

impl SourceCapture {
    /// The immutable capture request that was authenticated.
    pub fn request(&self) -> &SourceCaptureRequest {
        &self.request
    }

    /// Principal whose installed key authenticated the capture statement.
    pub fn signer(&self) -> &PrincipalId {
        &self.signer
    }
}

/// Exact signed captures for one institution workspace.
#[derive(Clone, Debug)]
pub struct TrustedSourceCaptureRegistry {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    captures: BTreeMap<SourceCaptureId, SourceCapture>,
}

impl TrustedSourceCaptureRegistry {
    /// Admit descriptor-bounded source captures signed by installed principals.
    ///
    /// # Errors
    ///
    /// Returns [`SourceCaptureRefusal`] when authentication fails, a manifest
    /// path escapes its declared root, or capture identities repeat.
    pub fn admit_signed(
        anchors: &InstitutionTrustAnchors,
        statements: impl IntoIterator<Item = SignedAdmissionWire<SourceCaptureRequest>>,
    ) -> Result<Self, SourceCaptureRefusal> {
        let mut captures = BTreeMap::new();
        for statement in statements {
            let admitted = anchors
                .admit_expected(AdmissionKind::SourceCapture, statement)
                .map_err(SourceCaptureRefusal::Authentication)?;
            let signer = admitted.signer().clone();
            let request = admitted.into_payload();
            if request.manifest.is_empty()
                || request.manifest.iter().any(|path| !relative_member(path))
            {
                return Err(SourceCaptureRefusal::InvalidManifest);
            }
            let capture = SourceCapture { request, signer };
            if captures
                .insert(capture.request.id.clone(), capture)
                .is_some()
            {
                return Err(SourceCaptureRefusal::DuplicateIdentity);
            }
        }
        Ok(Self {
            institution: anchors.institution().clone(),
            workspace: anchors.workspace().clone(),
            captures,
        })
    }

    /// Installed institution scope of this exact capture snapshot.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// Installed workspace scope of this exact capture snapshot.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Resolve one exact signed capture by its stable identity.
    pub fn resolve(&self, id: &SourceCaptureId) -> Option<&SourceCapture> {
        self.captures.get(id)
    }
}

/// Why a source capture did not enter its trusted registry.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceCaptureRefusal {
    /// Installed-key or exact-scope authentication failed.
    Authentication(AdmissionError),
    /// A selected manifest member was empty, absolute, or escaped its root.
    InvalidManifest,
    /// More than one statement used one capture identity.
    DuplicateIdentity,
}

impl std::fmt::Display for SourceCaptureRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication(error) => {
                write!(formatter, "source capture authentication failed: {error}")
            }
            Self::InvalidManifest => formatter
                .write_str("source capture manifest is not an explicit bounded relative selection"),
            Self::DuplicateIdentity => {
                formatter.write_str("source capture registry repeats an identity")
            }
        }
    }
}

impl std::error::Error for SourceCaptureRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            _ => None,
        }
    }
}

fn relative_member(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|member| !member.is_empty() && member != "." && member != "..")
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
        captures: &TrustedSourceCaptureRegistry,
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
        if captures.institution() != &workspace.institution || captures.workspace() != &workspace.id
        {
            return Err(ObservationAdmissionRefusal::ForeignCaptureScope);
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
            let capture = captures
                .resolve(&request.capture)
                .ok_or(ObservationAdmissionRefusal::CaptureNotAdmitted)?;
            let captured = capture.request();
            if captured.content_manifest_digest != request.capture_manifest_digest
                || captured.source != request.source
                || captured.adapter != request.adapter
                || captured.subject != request.subject
                || captured.statement != request.statement
                || captured.observed_at != request.observed_at
            {
                return Err(ObservationAdmissionRefusal::CaptureMismatch);
            }
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
                capture: request.capture.clone(),
                capture_manifest_digest: request.capture_manifest_digest.clone(),
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

    /// Resolve one exact signed-admitted observation by identity.
    ///
    /// This read-only view exposes the canonical admitted value for a later
    /// bounded consumer such as reconnaissance. It does not admit wire input
    /// or permit callers to replace the stored observation.
    pub fn resolve(&self, id: &ObservationId) -> Option<&Observation> {
        self.observations.get(id)
    }

    /// Resolve the sole observation that cites one admitted evidence record.
    pub fn resolve_by_evidence(&self, evidence: &EvidenceId) -> Option<&Observation> {
        let mut matching = self
            .observations
            .values()
            .filter(|observation| &observation.evidence == evidence);
        let observation = matching.next()?;
        matching.next().is_none().then_some(observation)
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
    /// The capture registry was admitted for another institution or workspace.
    ForeignCaptureScope,
    /// The cited source capture was absent from trusted admission.
    CaptureNotAdmitted,
    /// Capture descriptor/content or source fields differ from the observation.
    CaptureMismatch,
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
            Self::ForeignCaptureScope => {
                formatter.write_str("observation capture belongs to another trust scope")
            }
            Self::CaptureNotAdmitted => {
                formatter.write_str("observation source capture was not admitted")
            }
            Self::CaptureMismatch => {
                formatter.write_str("observation does not match its exact source capture")
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
    capture: &'a SourceCaptureId,
    capture_manifest_digest: &'a Digest,
    source: &'a str,
    adapter: &'a AdapterId,
    subject: &'a Digest,
    statement: &'a Digest,
    observed_at: Timestamp,
}

/// Derive the canonical payload digest required by an observation's evidence.
///
/// Service and acceptance adapters must call this while constructing the
/// signed [`crate::evidence::EvidenceRequest`] for the exact [`ObservationRequest`] they will
/// admit. The digest binds the workspace, source-capture identity and manifest,
/// source, adapter, subject, statement, and asserted observation time. It does
/// not authenticate either request; installed-key admission remains required
/// before either evidence or observation becomes trusted.
///
/// # Errors
///
/// Returns an error when the fixed observation-evidence payload cannot be
/// canonically encoded.
pub fn observation_evidence_payload_digest(
    workspace: &InstitutionWorkspaceId,
    request: &ObservationRequest,
) -> Result<Digest, crate::canonical::CanonicalError> {
    to_canonical_bytes(&ObservationEvidencePayload {
        kind: "observation_evidence_payload_v1",
        workspace,
        capture: &request.capture,
        capture_manifest_digest: &request.capture_manifest_digest,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CandidateClaim {
    id: ClaimId,
    workspace: InstitutionWorkspaceId,
    subject: Digest,
    proposition: Digest,
    supported_by: BTreeMap<String, BTreeSet<ObservationId>>,
    contradicted_by: BTreeMap<String, BTreeSet<ObservationId>>,
    missed_axes: BTreeSet<String>,
    interpreter: PrincipalId,
    interpreter_delegation: DelegationId,
}

/// Inert wire representation of a candidate claim before installed-key admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaimRequest {
    /// Stable identity of the candidate claim.
    pub id: ClaimId,
    /// Workspace in which the claim may be evaluated.
    pub workspace: InstitutionWorkspaceId,
    /// Digest of the subject the proposition concerns.
    pub subject: Digest,
    /// Digest of the proposed interpretation.
    pub proposition: Digest,
    /// Supporting observations grouped by their asserted source.
    pub supported_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Contradicting observations grouped by their asserted source.
    pub contradicted_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Reconnaissance axes the interpreter declares missing.
    pub missed_axes: BTreeSet<String>,
    /// Principal that interpreted the observations.
    pub interpreter: PrincipalId,
    /// Exact delegation used for the interpretation.
    pub interpreter_delegation: DelegationId,
}

impl From<CandidateClaimRequest> for CandidateClaim {
    fn from(request: CandidateClaimRequest) -> Self {
        Self {
            id: request.id,
            workspace: request.workspace,
            subject: request.subject,
            proposition: request.proposition,
            supported_by: request.supported_by,
            contradicted_by: request.contradicted_by,
            missed_axes: request.missed_axes,
            interpreter: request.interpreter,
            interpreter_delegation: request.interpreter_delegation,
        }
    }
}

impl From<&CandidateClaim> for CandidateClaimRequest {
    fn from(claim: &CandidateClaim) -> Self {
        Self {
            id: claim.id.clone(),
            workspace: claim.workspace.clone(),
            subject: claim.subject.clone(),
            proposition: claim.proposition.clone(),
            supported_by: claim.supported_by.clone(),
            contradicted_by: claim.contradicted_by.clone(),
            missed_axes: claim.missed_axes.clone(),
            interpreter: claim.interpreter.clone(),
            interpreter_delegation: claim.interpreter_delegation.clone(),
        }
    }
}

#[derive(Serialize)]
struct CandidateClaimDigestPayload<'a> {
    kind: &'static str,
    claim: &'a CandidateClaimRequest,
}

/// Derive the canonical digest an owner approval binds to one candidate claim.
///
/// This covers every candidate field, including support, contradiction,
/// interpreter, delegation, and declared gaps. It does not authenticate the
/// request; callers must admit the signed candidate through installed anchors.
///
/// # Errors
///
/// Returns an error when the fixed candidate payload cannot be canonically
/// encoded.
pub fn candidate_claim_digest(
    request: &CandidateClaimRequest,
) -> Result<Digest, crate::canonical::CanonicalError> {
    to_canonical_bytes(&CandidateClaimDigestPayload {
        kind: "candidate_claim_v1",
        claim: request,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Installed-key-admitted candidate claims for exactly one workspace.
#[derive(Clone, Debug, Default)]
pub struct TrustedCandidateClaimRegistry {
    workspace: Option<InstitutionWorkspaceId>,
    claims: BTreeMap<ClaimId, (CandidateClaim, Digest)>,
}

impl TrustedCandidateClaimRegistry {
    /// Admit interpreter-signed candidates after resolving every cited observation.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateAdmissionRefusal`] when a wire is unauthenticated,
    /// outside the installed workspace, signed by someone other than its named
    /// interpreter, or cites absent/rebound observations.
    pub fn admit_signed(
        workspace: &InstitutionWorkspace,
        anchors: &InstitutionTrustAnchors,
        observations: &TrustedObservationRegistry,
        statements: impl IntoIterator<Item = SignedAdmissionWire<CandidateClaimRequest>>,
    ) -> Result<Self, CandidateAdmissionRefusal> {
        if anchors.institution() != &workspace.institution || anchors.workspace() != &workspace.id {
            return Err(CandidateAdmissionRefusal::ForeignTrustScope);
        }
        if observations.workspace() != Some(&workspace.id) {
            return Err(CandidateAdmissionRefusal::ForeignWorkspace);
        }
        let mut claims = BTreeMap::new();
        for statement in statements {
            let admitted = anchors
                .admit_expected(AdmissionKind::CandidateClaim, statement)
                .map_err(CandidateAdmissionRefusal::Authentication)?;
            let signer = admitted.signer().clone();
            let digest = candidate_claim_digest(admitted.payload())
                .map_err(CandidateAdmissionRefusal::Encoding)?;
            let candidate = CandidateClaim::from(admitted.into_payload());
            if candidate.workspace != workspace.id {
                return Err(CandidateAdmissionRefusal::ForeignWorkspace);
            }
            if signer != candidate.interpreter {
                return Err(CandidateAdmissionRefusal::SignerInterpreterMismatch);
            }
            validate_claim_observations(&candidate, observations)
                .map_err(CandidateAdmissionRefusal::Observations)?;
            if claims
                .insert(candidate.id.clone(), (candidate, digest))
                .is_some()
            {
                return Err(CandidateAdmissionRefusal::DuplicateIdentity);
            }
        }
        Ok(Self {
            workspace: Some(workspace.id.clone()),
            claims,
        })
    }

    /// Resolve an exact admitted candidate claim.
    pub fn resolve(&self, id: &ClaimId) -> Option<&CandidateClaim> {
        self.claims.get(id).map(|(claim, _)| claim)
    }

    /// Return the canonical digest bound by a fact approval for this claim.
    pub fn digest(&self, id: &ClaimId) -> Option<&Digest> {
        self.claims.get(id).map(|(_, digest)| digest)
    }

    fn workspace(&self) -> Option<&InstitutionWorkspaceId> {
        self.workspace.as_ref()
    }
}

/// Why a candidate wire did not become an admitted candidate claim.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateAdmissionRefusal {
    /// Installed-key authentication failed.
    Authentication(AdmissionError),
    /// Candidate admission anchors belong to another workspace.
    ForeignTrustScope,
    /// Candidate or observation registry belongs to another workspace.
    ForeignWorkspace,
    /// The installed signer differs from the candidate's named interpreter.
    SignerInterpreterMismatch,
    /// A candidate identity was repeated in the admitted input.
    DuplicateIdentity,
    /// Candidate support or contradiction did not resolve to trusted observations.
    Observations(ApprovalRefusal),
    /// Candidate digest canonicalization failed.
    Encoding(crate::canonical::CanonicalError),
}

impl std::fmt::Display for CandidateAdmissionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication(error) => {
                write!(formatter, "candidate authentication failed: {error}")
            }
            Self::ForeignTrustScope => {
                formatter.write_str("installed anchors do not match candidate workspace")
            }
            Self::ForeignWorkspace => {
                formatter.write_str("candidate or observations belong to another workspace")
            }
            Self::SignerInterpreterMismatch => {
                formatter.write_str("candidate signer differs from named interpreter")
            }
            Self::DuplicateIdentity => {
                formatter.write_str("candidate registry repeats an identity")
            }
            Self::Observations(error) => {
                write!(formatter, "candidate observations are invalid: {error}")
            }
            Self::Encoding(error) => write!(formatter, "candidate digest encoding failed: {error}"),
        }
    }
}

impl std::error::Error for CandidateAdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            Self::Observations(error) => Some(error),
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

impl CandidateClaim {
    /// Candidate identity admitted from the signed request.
    pub fn id(&self) -> &ClaimId {
        &self.id
    }

    /// Workspace in which this candidate was admitted.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

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
    /// Canonical digest of the complete admitted candidate the owner saw.
    pub candidate_digest: Digest,
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
    /// The candidate, registry, or observations belongs to another workspace.
    ForeignWorkspace,
    /// The authenticated approval names no admitted candidate.
    CandidateNotAdmitted,
    /// The owner approval does not bind the admitted candidate's full digest.
    CandidateChanged,
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
            ApprovalRefusal::ForeignWorkspace => formatter.write_str(
                "claim, candidate registry, or observation belongs to another workspace",
            ),
            ApprovalRefusal::CandidateNotAdmitted => {
                formatter.write_str("approval names no admitted candidate claim")
            }
            ApprovalRefusal::CandidateChanged => {
                formatter.write_str("approval does not bind the admitted candidate claim")
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
    candidates: &TrustedCandidateClaimRegistry,
    approval: SignedAdmissionWire<FactApprovalRequest>,
) -> Result<ApprovedFact, ApprovalRefusal> {
    if anchors.institution() != &workspace.institution || anchors.workspace() != &workspace.id {
        return Err(ApprovalRefusal::ForeignTrustScope);
    }
    if candidates.workspace() != Some(&workspace.id)
        || observations.workspace() != Some(&workspace.id)
    {
        return Err(ApprovalRefusal::ForeignWorkspace);
    }

    let admitted = anchors
        .admit_expected(AdmissionKind::FactApproval, approval)
        .map_err(ApprovalRefusal::Authentication)?;
    if admitted.signer() != &workspace.owner {
        return Err(ApprovalRefusal::NotInstitutionOwner);
    }
    let approval = admitted.payload();
    let claim = candidates
        .resolve(&approval.claim)
        .ok_or(ApprovalRefusal::CandidateNotAdmitted)?;
    if candidates.digest(&approval.claim) != Some(&approval.candidate_digest) {
        return Err(ApprovalRefusal::CandidateChanged);
    }
    validate_claim_observations(claim, observations)?;
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
            capture: SourceCaptureId::new(),
            capture_manifest_digest: Digest::blake3(b"fixture capture manifest"),
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
                BTreeSet::from([AdmissionKind::CandidateClaim, AdmissionKind::FactApproval]),
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
            interpreter: fixture.owner.clone(),
            interpreter_delegation: fixture.workspace.owner_delegation.clone(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "authenticated fixture candidates must encode canonically"
    )]
    fn candidates(fixture: &Fixture, claim: &CandidateClaim) -> TrustedCandidateClaimRegistry {
        admit_candidate(fixture, claim).expect("fixture candidate is admitted")
    }

    fn admit_candidate(
        fixture: &Fixture,
        claim: &CandidateClaim,
    ) -> Result<TrustedCandidateClaimRegistry, CandidateAdmissionRefusal> {
        TrustedCandidateClaimRegistry::admit_signed(
            &fixture.workspace,
            &fixture.anchors,
            &fixture.registry,
            [SignedAdmissionWire::sign(
                AdmissionKind::CandidateClaim,
                fixture.workspace.institution.clone(),
                fixture.workspace.id.clone(),
                fixture.owner.clone(),
                CandidateClaimRequest::from(claim),
                &fixture.owner_key,
            )
            .expect("fixture candidate encodes")],
        )
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
                candidate_digest: candidate_claim_digest(&CandidateClaimRequest::from(claim))
                    .expect("fixture candidate encodes"),
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
            &candidates(&fixture, &candidate),
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
    fn approval_binds_the_exact_signed_candidate_for_restart_re_admission() {
        let fixture = fixture_with_observation();
        let original = claim(&fixture, false);
        let approval = approval(
            &fixture,
            &original,
            fixture.owner.clone(),
            &fixture.owner_key,
        );
        let reloaded = candidates(&fixture, &original);
        let fact = approve_claim(
            &fixture.workspace,
            &fixture.registry,
            &fixture.anchors,
            &reloaded,
            approval.clone(),
        )
        .expect("the same signed candidate re-admits after restart");
        assert_eq!(fact.claim(), &original.id);

        let mut altered = original;
        altered.contradicted_by = altered.supported_by.clone();
        assert!(matches!(
            approve_claim(
                &fixture.workspace,
                &fixture.registry,
                &fixture.anchors,
                &candidates(&fixture, &altered),
                approval,
            ),
            Err(ApprovalRefusal::CandidateChanged)
        ));
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
                &candidates(&fixture, &candidate),
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
                candidate_digest: candidate_claim_digest(&CandidateClaimRequest::from(&candidate))
                    .expect("fixture candidate encodes"),
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
                &candidates(&fixture, &candidate),
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
                candidate_digest: candidate_claim_digest(&CandidateClaimRequest::from(&candidate))
                    .expect("fixture candidate encodes"),
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
                &candidates(&fixture, &candidate),
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
            capture: SourceCaptureId::new(),
            capture_manifest_digest: Digest::blake3(b"forged capture manifest"),
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

    #[expect(
        clippy::expect_used,
        reason = "fixture capture must pass through exact signed admission"
    )]
    fn captures(
        fixture: &Fixture,
        anchors: &InstitutionTrustAnchors,
        request: &ObservationRequest,
    ) -> TrustedSourceCaptureRegistry {
        TrustedSourceCaptureRegistry::admit_signed(
            anchors,
            [SignedAdmissionWire::sign(
                AdmissionKind::SourceCapture,
                fixture.workspace.institution.clone(),
                fixture.workspace.id.clone(),
                fixture.owner.clone(),
                SourceCaptureRequest {
                    id: request.capture.clone(),
                    source: request.source.clone(),
                    adapter: request.adapter.clone(),
                    subject: request.subject.clone(),
                    statement: request.statement.clone(),
                    observed_at: request.observed_at,
                    reconnaissance_delegation: fixture.workspace.owner_delegation.clone(),
                    reconnaissance: crate::reconnaissance::ReconnaissanceScope {
                        commissioner: fixture.owner.clone(),
                        delegation: fixture.workspace.owner_delegation.clone(),
                        sources: BTreeSet::from([request.source.clone()]),
                        adapters: BTreeSet::from([request.adapter.clone()]),
                        expires_at: request.observed_at + jiff::SignedDuration::from_hours(1),
                    },
                    manifest: BTreeSet::from(["snapshot.json".to_string()]),
                    descriptor_digest: Digest::blake3(b"capture descriptor"),
                    content_manifest_digest: request.capture_manifest_digest.clone(),
                },
                &fixture.owner_key,
            )
            .expect("fixture capture encodes")],
        )
        .expect("fixture capture is admitted")
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
                    BTreeSet::from([
                        AdmissionKind::Evidence,
                        AdmissionKind::Observation,
                        AdmissionKind::SourceCapture,
                    ]),
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
            capture: SourceCaptureId::new(),
            capture_manifest_digest: Digest::blake3(b"capture manifest"),
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
        let captures = captures(&fixture, &anchors, &request);
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
                &captures,
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
                BTreeSet::from([
                    AdmissionKind::Evidence,
                    AdmissionKind::Observation,
                    AdmissionKind::SourceCapture,
                ]),
            )
            .expect("fixture key is valid")],
        )
        .expect("fixture principal is unique");
        let request = ObservationRequest {
            id: ObservationId::new(),
            capture: SourceCaptureId::new(),
            capture_manifest_digest: Digest::blake3(b"capture manifest"),
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
        let captures = captures(&fixture, &anchors, &request);
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
            &captures,
            [wire.clone()],
        )
        .expect("exact signed observation is admitted");
        let reloaded = TrustedObservationRegistry::admit_signed(
            &fixture.workspace,
            &anchors,
            &evidence,
            &captures,
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
                &captures,
                [mismatched],
            ),
            Err(ObservationAdmissionRefusal::CaptureMismatch)
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
                &candidates(&fixture, &candidate),
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
                &candidates(&fixture, &candidate),
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
            admit_candidate(&fixture, &fabricated),
            Err(CandidateAdmissionRefusal::Observations(
                ApprovalRefusal::ObservationNotAdmitted { .. }
            ))
        ));
    }
}
