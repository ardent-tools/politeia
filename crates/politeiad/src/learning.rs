//! Pure institutional learning projections.
//!
//! This module deliberately receives an already authenticated snapshot from a
//! service coordinator. It neither admits transport input nor writes state.
//! Facts are canonical [`ApprovedFact`] values, feedback is an inert proposal,
//! and corrections are projected by `politeia-evidence`'s append-only relation
//! algebra rather than by a second mutation path.

use std::collections::{BTreeMap, BTreeSet};

use politeia_core::{
    AdapterId, DataClass, Delegation, Digest, EvidenceId, ExecutionResourceId, InstitutionId,
    InstitutionWorkspaceId, ObservationId, OperationId, PrincipalId, RuntimeGenerationId,
    institution::TrustDomainId, knowledge::ApprovedFact,
};
use politeia_evidence::{
    TrustedEvidenceRegistry,
    assessment::{self, AssessmentError, AssessmentRelation, Projection},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Delegated action required to compile context.
pub const COMPILE_CONTEXT_ACTION: &str = "context.compile";

/// A source's status in the approved institutional model.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeCurrency {
    /// The source is canonical institutional knowledge.
    Canonical,
    /// The source is preserved history and cannot outrank canonical knowledge.
    Archive,
}

/// One approved fact and the exact provenance eligible for context compilation.
#[derive(Clone, Debug)]
pub struct ContextSource {
    /// Stable source identity used in deterministic output and diagnostics.
    pub id: EvidenceId,
    /// Institution-owned fact; construction required canonical owner approval.
    pub fact: ApprovedFact,
    /// Exact observation identities behind the source.
    pub observations: BTreeSet<ObservationId>,
    /// Exact admitted evidence identities behind the source.
    pub evidence: BTreeSet<EvidenceId>,
    /// Adapter that produced the source observation.
    pub adapter: AdapterId,
    /// Current canonical truth or preserved archive.
    pub currency: KnowledgeCurrency,
    /// Data classifications carried by the source.
    pub data_classes: BTreeSet<DataClass>,
    /// Institutional audiences allowed to receive it.
    pub audiences: BTreeSet<String>,
    /// Named sinks eligible to receive it.
    pub sinks: BTreeSet<String>,
    /// Trust domain in which this source may be compiled.
    pub trust_domain: TrustDomainId,
    /// Deterministic relevance supplied only after admission of this source.
    pub relevance: u32,
}

/// Approved active-generation capability inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveCapabilities {
    /// Operations admitted in the active generation.
    pub operations: BTreeSet<OperationId>,
    /// Execution-resource identities admitted in the active generation.
    pub resources: BTreeSet<ExecutionResourceId>,
}

/// Coordinator-supplied, authenticated institutional learning input.
#[derive(Clone, Debug)]
pub struct LearningSnapshot {
    /// Institution owning every source in this snapshot.
    pub institution: InstitutionId,
    /// Institution workspace owning every source in this snapshot.
    pub workspace: InstitutionWorkspaceId,
    /// Exact active generation from which discovery may be reported.
    pub generation: RuntimeGenerationId,
    /// Client-owned trust domain for this compilation.
    pub trust_domain: TrustDomainId,
    /// Version of the deterministic context compiler.
    pub compiler_version: String,
    /// Approved institutional sources. The coordinator must exclude unadmitted
    /// observations before constructing this value.
    pub sources: Vec<ContextSource>,
    /// Capability identities from the approved active generation only.
    pub capabilities: ActiveCapabilities,
}

/// Inert context-compilation request received by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRequest {
    /// Institution expected by the caller.
    pub institution: InstitutionId,
    /// Workspace expected by the caller.
    pub workspace: InstitutionWorkspaceId,
    /// Active generation expected by the caller.
    pub generation: RuntimeGenerationId,
    /// Compiler version expected by the caller.
    pub compiler_version: String,
    /// Institutional audience for the requested context.
    pub audience: String,
    /// Named receiving sink.
    pub sink: String,
    /// Trust domain in which the caller will use the context.
    pub trust_domain: TrustDomainId,
    /// Maximum selected sources.
    pub limit: usize,
}

/// One context item selected only after authorization filtering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextItem {
    /// Selected source identity.
    pub source: EvidenceId,
    /// Adapter that produced the admitted source observation.
    pub adapter: AdapterId,
    /// Approved claim identity.
    pub claim: politeia_core::ClaimId,
    /// Exact subject digest.
    pub subject: Digest,
    /// Exact approved proposition digest.
    pub proposition: Digest,
    /// Evidence identities supporting the selected fact.
    pub evidence: BTreeSet<EvidenceId>,
    /// Observation identities supporting the selected fact.
    pub observations: BTreeSet<ObservationId>,
}

/// Deterministic context compiler output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledContext {
    /// Input generation bound into this result.
    pub generation: RuntimeGenerationId,
    /// Compiler version that ranked the sources.
    pub compiler_version: String,
    /// Selected source IDs in deterministic ranking order.
    pub input_ids: Vec<EvidenceId>,
    /// Context available for the bounded request.
    pub items: Vec<ContextItem>,
}

/// Why context compilation refused the request before inspecting source content.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextRefusal {
    /// Request and authenticated snapshot describe different institution state.
    SnapshotMismatch,
    /// Compiler versions differ.
    CompilerVersionMismatch,
    /// The requester is not the delegation subject.
    RequesterMismatch,
    /// Context compilation was not delegated.
    ActionNotDelegated,
    /// The delegation is expired at the supplied coordinator time.
    StaleDelegation,
}

impl std::fmt::Display for ContextRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SnapshotMismatch => {
                formatter.write_str("context request does not match learning snapshot")
            }
            Self::CompilerVersionMismatch => {
                formatter.write_str("context compiler version does not match snapshot")
            }
            Self::RequesterMismatch => {
                formatter.write_str("context requester differs from delegation subject")
            }
            Self::ActionNotDelegated => {
                formatter.write_str("context compilation was not delegated")
            }
            Self::StaleDelegation => formatter.write_str("context delegation was expired"),
        }
    }
}

impl std::error::Error for ContextRefusal {}

/// Compile bounded context after all authority and data filters have run.
///
/// Sources that fail an eligibility predicate do not enter the ranking vector,
/// the returned IDs, or any refusal diagnostic. Ranking is deterministic:
/// canonical sources outrank archives, then relevance descends, then source ID.
///
/// # Errors
///
/// Returns [`ContextRefusal`] when the snapshot, compiler, or delegation is
/// not exact. An eligible-empty result is valid and contains no source details.
pub fn compile_context(
    snapshot: &LearningSnapshot,
    requester: &PrincipalId,
    delegation: &Delegation,
    request: &ContextRequest,
    now: jiff::Timestamp,
) -> Result<CompiledContext, ContextRefusal> {
    if request.institution != snapshot.institution
        || request.workspace != snapshot.workspace
        || request.generation != snapshot.generation
        || request.trust_domain != snapshot.trust_domain
    {
        return Err(ContextRefusal::SnapshotMismatch);
    }
    if request.compiler_version != snapshot.compiler_version {
        return Err(ContextRefusal::CompilerVersionMismatch);
    }
    if delegation.subject != *requester {
        return Err(ContextRefusal::RequesterMismatch);
    }
    if !delegation.actions.contains(COMPILE_CONTEXT_ACTION) {
        return Err(ContextRefusal::ActionNotDelegated);
    }
    if delegation.is_expired(now) {
        return Err(ContextRefusal::StaleDelegation);
    }

    let mut eligible: Vec<&ContextSource> = snapshot
        .sources
        .iter()
        .filter(|source| {
            source.trust_domain == request.trust_domain
                && source.audiences.contains(&request.audience)
                && source.sinks.contains(&request.sink)
                && source.data_classes.is_subset(&delegation.data_classes)
                && delegation.audience.contains(&request.audience)
        })
        .collect();
    eligible.sort_by(|left, right| {
        left.currency
            .cmp(&right.currency)
            .then_with(|| right.relevance.cmp(&left.relevance))
            .then_with(|| left.id.cmp(&right.id))
    });
    eligible.truncate(request.limit);

    let items: Vec<ContextItem> = eligible
        .into_iter()
        .map(|source| ContextItem {
            source: source.id.clone(),
            adapter: source.adapter.clone(),
            claim: source.fact.claim().clone(),
            subject: source.fact.subject().clone(),
            proposition: source.fact.proposition().clone(),
            evidence: source.evidence.clone(),
            observations: source.observations.clone(),
        })
        .collect();
    Ok(CompiledContext {
        generation: snapshot.generation.clone(),
        compiler_version: snapshot.compiler_version.clone(),
        input_ids: items.iter().map(|item| item.source.clone()).collect(),
        items,
    })
}

/// Inert request to discover only active-generation capability identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    /// Institution expected by the caller.
    pub institution: InstitutionId,
    /// Workspace expected by the caller.
    pub workspace: InstitutionWorkspaceId,
    /// Active generation expected by the caller.
    pub generation: RuntimeGenerationId,
}

/// Descriptive active-generation capabilities, carrying no authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDiscovery {
    /// Generation from which each identity was read.
    pub generation: RuntimeGenerationId,
    /// Approved operation identities.
    pub operations: BTreeSet<OperationId>,
    /// Approved execution-resource identities.
    pub resources: BTreeSet<ExecutionResourceId>,
}

/// Discover capability labels from the approved active generation.
///
/// The result is descriptive. It is not a delegation, policy decision, effect
/// lease, or permission to exercise any listed capability.
///
/// # Errors
///
/// Returns [`ContextRefusal::SnapshotMismatch`] for a request outside the
/// exact active generation.
pub fn discover_capabilities(
    snapshot: &LearningSnapshot,
    request: &CapabilityRequest,
) -> Result<CapabilityDiscovery, ContextRefusal> {
    if request.institution != snapshot.institution
        || request.workspace != snapshot.workspace
        || request.generation != snapshot.generation
    {
        return Err(ContextRefusal::SnapshotMismatch);
    }
    Ok(CapabilityDiscovery {
        generation: snapshot.generation.clone(),
        operations: snapshot.capabilities.operations.clone(),
        resources: snapshot.capabilities.resources.clone(),
    })
}

/// Inert feedback submitted about a selected context item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackRequest {
    /// Institution expected by the feedback producer.
    pub institution: InstitutionId,
    /// Workspace expected by the feedback producer.
    pub workspace: InstitutionWorkspaceId,
    /// Generation that compiled the context.
    pub generation: RuntimeGenerationId,
    /// Source the feedback concerns.
    pub source: EvidenceId,
    /// Observation the feedback relies on.
    pub observation: ObservationId,
    /// Evidence the feedback relies on.
    pub evidence: EvidenceId,
    /// Digest of the feedback content held by the coordinator.
    pub feedback_digest: Digest,
}

/// An inert proposal derived from feedback; it cannot alter approved facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrectionProposal {
    /// Exact source whose interpretation may need correction.
    pub source: EvidenceId,
    /// Existing observation cited by the feedback.
    pub observation: ObservationId,
    /// Existing evidence cited by the feedback.
    pub evidence: EvidenceId,
    /// Opaque feedback content binding.
    pub feedback_digest: Digest,
}

/// Why feedback did not become a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeedbackRefusal {
    /// The feedback belongs to another snapshot.
    SnapshotMismatch,
    /// The named source is absent from the authenticated snapshot.
    MissingSource,
    /// The named observation is not provenance of that source.
    MissingObservation,
    /// The named evidence is not provenance of that source.
    MissingEvidence,
}

impl std::fmt::Display for FeedbackRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SnapshotMismatch => {
                formatter.write_str("feedback does not match learning snapshot")
            }
            Self::MissingSource => formatter.write_str("feedback names no approved context source"),
            Self::MissingObservation => {
                formatter.write_str("feedback observation is not source provenance")
            }
            Self::MissingEvidence => {
                formatter.write_str("feedback evidence is not source provenance")
            }
        }
    }
}

impl std::error::Error for FeedbackRefusal {}

/// Turn feedback into an inert correction proposal.
///
/// This function does not approve a fact, create an assessment relation, or
/// alter the snapshot. The coordinator must separately authenticate a later
/// owner-authorized correction using the evidence relation machinery.
///
/// # Errors
///
/// Returns [`FeedbackRefusal`] when the feedback does not cite exact approved
/// source provenance.
pub fn record_feedback(
    snapshot: &LearningSnapshot,
    feedback: &FeedbackRequest,
) -> Result<CorrectionProposal, FeedbackRefusal> {
    if feedback.institution != snapshot.institution
        || feedback.workspace != snapshot.workspace
        || feedback.generation != snapshot.generation
    {
        return Err(FeedbackRefusal::SnapshotMismatch);
    }
    let source = snapshot
        .sources
        .iter()
        .find(|source| source.id == feedback.source)
        .ok_or(FeedbackRefusal::MissingSource)?;
    if !source.observations.contains(&feedback.observation) {
        return Err(FeedbackRefusal::MissingObservation);
    }
    if !source.evidence.contains(&feedback.evidence) {
        return Err(FeedbackRefusal::MissingEvidence);
    }
    Ok(CorrectionProposal {
        source: feedback.source.clone(),
        observation: feedback.observation.clone(),
        evidence: feedback.evidence.clone(),
        feedback_digest: feedback.feedback_digest.clone(),
    })
}

/// Project an owner-authorized correction or supersession over preserved evidence.
///
/// This is a deliberately thin call to the canonical append-only assessment
/// algebra. The returned view contains exact original evidence IDs; it never
/// rewrites their bytes or treats an ambiguous graph as a correction.
///
/// # Errors
///
/// Returns [`AssessmentError`] when an asserted relation lacks an exact record
/// or valid delegated authority.
pub fn correction_view(
    subject: &Digest,
    evidence: &TrustedEvidenceRegistry,
    relations: &[AssessmentRelation],
    delegations: &BTreeMap<politeia_core::DelegationId, Delegation>,
) -> Result<Projection, AssessmentError> {
    assessment::project(subject, evidence, relations, delegations)
}
