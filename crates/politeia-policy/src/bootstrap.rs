//! Built-in authorization for the first descriptor-bounded source read.
//!
//! Before an institution has an active generated runtime, it cannot run the
//! ordinary detector-backed policy path. This module admits one deliberately
//! narrow exception: an installed owner may directly delegate one exact,
//! read-only source capture to a commissioner. The resulting decision still
//! binds the installed policy and the runtime's canonical operation-intent
//! digest. It does not manufacture a clean control result.

use std::collections::BTreeSet;

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::institution::InstitutionWorkspace;
use politeia_core::knowledge::{SourceCaptureRequest, TrustedSourceCaptureRegistry};
use politeia_core::reconnaissance::{
    RECONNOITRE_ACTION, ReconnaissanceRefusal, ReconnaissanceScope,
};
use politeia_core::trust::{AdmissionKind, Admitted};
use politeia_core::{
    DataClass, Delegation, Digest, Effect, OperationId, OperationSpec, PrincipalId, SourceCaptureId,
};
use serde::Serialize;

use crate::PolicyDecision;

/// Stable identity of the built-in pre-generation reconnaissance rule.
pub const BOOTSTRAP_RECONNAISSANCE_BINDING: &str = "politeia.bootstrap.reconnaissance.capture.v1";

/// Exact operation name admitted by the built-in reconnaissance rule.
pub const BOOTSTRAP_RECONNAISSANCE_OPERATION: &str = "bootstrap.reconnaissance.capture.v1";

/// Evidence the source-capture port owes after the authorized read.
pub const SOURCE_CAPTURE_MANIFEST_EVIDENCE: &str = "source_capture.manifest.v1";

/// One pre-generation source-read evaluation.
///
/// `intent_digest` must be the digest of the complete runtime
/// `OperationIntent`. The dispatcher independently recomputes and compares it
/// before issuing a lease, while this crate stays upstream of the runtime and
/// avoids a dependency cycle.
pub struct BootstrapReconnaissance<'a> {
    /// Installed owner-approved workspace.
    pub workspace: &'a InstitutionWorkspace,
    /// Installed-scope registry containing the authenticated capture request.
    pub captures: &'a TrustedSourceCaptureRegistry,
    /// Exact capture selected for this operation.
    pub capture: &'a SourceCaptureId,
    /// Authenticated owner-issued reconnaissance delegation.
    pub delegation: &'a Admitted<Delegation>,
    /// Descriptor bounding the commissioner, source, adapter, and lifetime.
    pub scope: &'a ReconnaissanceScope,
    /// Principal requesting the runtime operation.
    pub principal: &'a PrincipalId,
    /// Exact registered operation contract.
    pub operation: &'a OperationSpec,
    /// Exact resources carried by the runtime operation intent.
    pub resources: &'a BTreeSet<String>,
    /// Canonical digest of the complete runtime operation intent.
    pub intent_digest: &'a Digest,
    /// Digest of the owner-signed immutable bootstrap record used by storage.
    pub bootstrap_record_digest: &'a Digest,
    /// Trusted authorization instant.
    pub at: Timestamp,
}

/// Construct the sole operation shape admitted before a generated runtime is active.
pub fn bootstrap_reconnaissance_operation(
    id: OperationId,
    data_classes: BTreeSet<DataClass>,
) -> OperationSpec {
    OperationSpec {
        id,
        name: BOOTSTRAP_RECONNAISSANCE_OPERATION.to_string(),
        actions: BTreeSet::from([RECONNOITRE_ACTION.to_string()]),
        effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes,
        evidence_obligations: vec![SOURCE_CAPTURE_MANIFEST_EVIDENCE.to_string()],
        execution_requirement: None,
        retryable: false,
        requires_idempotency: false,
    }
}

/// Derive the exact resource set shared by policy, dispatcher, and capture port.
pub fn bootstrap_capture_resources(capture: &SourceCaptureRequest) -> BTreeSet<String> {
    BTreeSet::from([
        format!("capture:{}", capture.id.0),
        format!("source:{}", capture.source),
        format!("adapter:{}", capture.adapter.0),
        format!("capture-descriptor:{}", capture.descriptor_digest.as_str()),
        format!(
            "capture-manifest:{}",
            capture.content_manifest_digest.as_str()
        ),
    ])
}

/// Evaluate the one source read needed to acquire pre-generation observations.
///
/// # Errors
///
/// Returns [`BootstrapRefusal`] unless every authenticated authority, installed
/// scope, capture, operation, and intent axis agrees exactly.
pub fn evaluate_bootstrap_reconnaissance(
    request: &BootstrapReconnaissance<'_>,
) -> Result<PolicyDecision, BootstrapRefusal> {
    if request.captures.institution() != &request.workspace.institution {
        return Err(BootstrapRefusal::ForeignCaptureInstitution);
    }
    if request.captures.workspace() != &request.workspace.id {
        return Err(BootstrapRefusal::ForeignCaptureWorkspace);
    }
    let capture = request
        .captures
        .resolve(request.capture)
        .ok_or(BootstrapRefusal::CaptureNotAdmitted)?;
    let capture_request = capture.request();

    admit_delegation(request, capture_request, capture.signer())?;
    admit_scope(request, capture_request)?;
    admit_operation(request, capture_request)?;

    let subject = canonical_digest(&BootstrapSubject {
        kind: BOOTSTRAP_RECONNAISSANCE_BINDING,
        institution: &request.workspace.institution,
        workspace: &request.workspace.id,
        bootstrap_record: request.bootstrap_record_digest,
        delegation: request.delegation.payload(),
        scope: request.scope,
        capture: capture_request,
        operation: request.operation,
        principal: request.principal,
        resources: request.resources,
        intent: request.intent_digest,
    })?;
    let population = canonical_digest(&CapturePopulation {
        kind: "politeia.source-capture.population.v1",
        capture: &capture_request.id,
        source: &capture_request.source,
        adapter: &capture_request.adapter,
        manifest: &capture_request.manifest,
        descriptor: &capture_request.descriptor_digest,
        content_manifest: &capture_request.content_manifest_digest,
    })?;

    Ok(PolicyDecision {
        bundle: request.workspace.policy_bundle.clone(),
        policy_digest: request.workspace.policy_digest.clone(),
        intent_digest: request.intent_digest.clone(),
        subject,
        population,
        principal: request.principal.clone(),
        allowed: true,
        binding_ids: vec![BOOTSTRAP_RECONNAISSANCE_BINDING.to_string()],
        control_runs: Vec::new(),
        activation_proofs: Vec::new(),
        waiver_ids: Vec::new(),
        reasons: vec![
            "installed owner directly delegated this descriptor-bound read-only capture"
                .to_string(),
        ],
    })
}

fn admit_delegation(
    request: &BootstrapReconnaissance<'_>,
    capture: &SourceCaptureRequest,
    capture_signer: &PrincipalId,
) -> Result<(), BootstrapRefusal> {
    let admitted = request.delegation;
    if admitted.kind() != AdmissionKind::Delegation {
        return Err(BootstrapRefusal::UnexpectedDelegationKind);
    }
    if admitted.institution() != &request.workspace.institution {
        return Err(BootstrapRefusal::ForeignDelegationInstitution);
    }
    if admitted.workspace() != &request.workspace.id {
        return Err(BootstrapRefusal::ForeignDelegationWorkspace);
    }
    let delegation = admitted.payload();
    if admitted.signer() != &delegation.issuer {
        return Err(BootstrapRefusal::DelegationSignerMismatch);
    }
    if delegation.issuer != request.workspace.owner {
        return Err(BootstrapRefusal::DelegationIssuerNotOwner);
    }
    if delegation.parent.is_some() {
        return Err(BootstrapRefusal::IndirectDelegation);
    }
    if delegation.issuer == delegation.subject {
        return Err(BootstrapRefusal::SelfDelegation);
    }
    if &delegation.subject != request.principal
        || capture_signer != request.principal
        || request.scope.commissioner != *request.principal
    {
        return Err(BootstrapRefusal::PrincipalMismatch);
    }
    if delegation.id != capture.reconnaissance_delegation
        || delegation.id != request.scope.delegation
    {
        return Err(BootstrapRefusal::CaptureDelegationMismatch);
    }
    let expected_actions = BTreeSet::from([RECONNOITRE_ACTION.to_string()]);
    if delegation.actions != expected_actions {
        return Err(BootstrapRefusal::DelegatedActionMismatch);
    }
    let expected_resources = bootstrap_capture_resources(capture);
    if delegation.resources != expected_resources {
        return Err(BootstrapRefusal::DelegatedResourceMismatch);
    }
    let expected_effects = BTreeSet::from([Effect::ReadExternalSystem]);
    if delegation.effects != expected_effects {
        return Err(BootstrapRefusal::DelegatedEffectMismatch);
    }
    let expected_audience =
        BTreeSet::from([format!("institution:{}", request.workspace.institution.0)]);
    if delegation.audience != expected_audience {
        return Err(BootstrapRefusal::DelegatedAudienceMismatch);
    }
    if !delegation.budget.is_finite() {
        return Err(BootstrapRefusal::UnboundedDelegationBudget);
    }
    Ok(())
}

fn admit_scope(
    request: &BootstrapReconnaissance<'_>,
    capture: &SourceCaptureRequest,
) -> Result<(), BootstrapRefusal> {
    request
        .scope
        .admit_authority(request.delegation.payload(), request.at)
        .map_err(BootstrapRefusal::ReconnaissanceAuthority)?;
    if request.scope.expires_at > request.delegation.payload().expires_at {
        return Err(BootstrapRefusal::ScopeOutlivesDelegation);
    }
    if capture.observed_at >= request.scope.expires_at
        || capture.observed_at >= request.delegation.payload().expires_at
    {
        return Err(BootstrapRefusal::CaptureAfterExpiry);
    }
    let expected_sources = BTreeSet::from([capture.source.clone()]);
    if request.scope.sources != expected_sources {
        return Err(BootstrapRefusal::SourceScopeMismatch);
    }
    let expected_adapters = BTreeSet::from([capture.adapter.clone()]);
    if request.scope.adapters != expected_adapters {
        return Err(BootstrapRefusal::AdapterScopeMismatch);
    }
    Ok(())
}

fn admit_operation(
    request: &BootstrapReconnaissance<'_>,
    capture: &SourceCaptureRequest,
) -> Result<(), BootstrapRefusal> {
    if request.operation.name != BOOTSTRAP_RECONNAISSANCE_OPERATION {
        return Err(BootstrapRefusal::OperationNameMismatch);
    }
    if request.operation.actions != BTreeSet::from([RECONNOITRE_ACTION.to_string()]) {
        return Err(BootstrapRefusal::OperationActionMismatch);
    }
    if request.operation.effects != BTreeSet::from([Effect::ReadExternalSystem]) {
        return Err(BootstrapRefusal::OperationEffectMismatch);
    }
    if request.operation.data_classes != request.delegation.payload().data_classes {
        return Err(BootstrapRefusal::OperationDataMismatch);
    }
    if request.operation.evidence_obligations != [SOURCE_CAPTURE_MANIFEST_EVIDENCE.to_string()] {
        return Err(BootstrapRefusal::OperationEvidenceMismatch);
    }
    if request.operation.execution_requirement.is_some() {
        return Err(BootstrapRefusal::OperationRequiresExecutionAssignment);
    }
    if request.operation.retryable || request.operation.requires_idempotency {
        return Err(BootstrapRefusal::OperationRetryMismatch);
    }
    let expected_resources = bootstrap_capture_resources(capture);
    if request.resources != &expected_resources {
        return Err(BootstrapRefusal::IntentResourceMismatch);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<Digest, BootstrapRefusal> {
    to_canonical_bytes(value)
        .map(|bytes| Digest::blake3(&bytes))
        .map_err(BootstrapRefusal::Encoding)
}

#[derive(Serialize)]
struct BootstrapSubject<'a> {
    kind: &'static str,
    institution: &'a politeia_core::InstitutionId,
    workspace: &'a politeia_core::InstitutionWorkspaceId,
    bootstrap_record: &'a Digest,
    delegation: &'a Delegation,
    scope: &'a ReconnaissanceScope,
    capture: &'a SourceCaptureRequest,
    operation: &'a OperationSpec,
    principal: &'a PrincipalId,
    resources: &'a BTreeSet<String>,
    intent: &'a Digest,
}

#[derive(Serialize)]
struct CapturePopulation<'a> {
    kind: &'static str,
    capture: &'a SourceCaptureId,
    source: &'a str,
    adapter: &'a politeia_core::AdapterId,
    manifest: &'a BTreeSet<String>,
    descriptor: &'a Digest,
    content_manifest: &'a Digest,
}

/// Why the built-in pre-generation rule refused a source read.
#[derive(Debug)]
#[non_exhaustive]
pub enum BootstrapRefusal {
    /// Capture admission belongs to another institution.
    ForeignCaptureInstitution,
    /// Capture admission belongs to another workspace.
    ForeignCaptureWorkspace,
    /// The selected capture identity was not admitted.
    CaptureNotAdmitted,
    /// The authority payload was admitted for another semantic kind.
    UnexpectedDelegationKind,
    /// Delegation admission belongs to another institution.
    ForeignDelegationInstitution,
    /// Delegation admission belongs to another workspace.
    ForeignDelegationWorkspace,
    /// Authenticated signer differs from the delegation issuer.
    DelegationSignerMismatch,
    /// Direct delegation was not issued by the installed workspace owner.
    DelegationIssuerNotOwner,
    /// This bootstrap boundary does not interpret a delegated chain.
    IndirectDelegation,
    /// The authority holder issued its own grant.
    SelfDelegation,
    /// Capture signer, scope commissioner, delegation subject, and requester differ.
    PrincipalMismatch,
    /// Capture or scope names another delegation.
    CaptureDelegationMismatch,
    /// Delegation action is broader than the one built-in action.
    DelegatedActionMismatch,
    /// Delegation resources differ from the exact capture resources.
    DelegatedResourceMismatch,
    /// Delegation effect is not the sole external-system read.
    DelegatedEffectMismatch,
    /// Delegation audience is not the exact installed institution.
    DelegatedAudienceMismatch,
    /// Delegation budget leaves one or more resource dimensions unbounded.
    UnboundedDelegationBudget,
    /// Core reconnaissance authority validation failed.
    ReconnaissanceAuthority(ReconnaissanceRefusal),
    /// Reconnaissance scope lasts longer than its delegation.
    ScopeOutlivesDelegation,
    /// Signed capture time is outside the delegated scope.
    CaptureAfterExpiry,
    /// Scope names more, fewer, or different sources than the capture.
    SourceScopeMismatch,
    /// Scope names more, fewer, or different adapters than the capture.
    AdapterScopeMismatch,
    /// Operation name is not the built-in source-capture operation.
    OperationNameMismatch,
    /// Operation action differs from the sole reconnaissance action.
    OperationActionMismatch,
    /// Operation effect differs from the sole external-system read.
    OperationEffectMismatch,
    /// Operation and delegation data classifications differ.
    OperationDataMismatch,
    /// Operation does not owe the exact capture-manifest evidence.
    OperationEvidenceMismatch,
    /// Bootstrap reconnaissance attempted to select an execution resource.
    OperationRequiresExecutionAssignment,
    /// Bootstrap reconnaissance attempted retry or idempotency semantics.
    OperationRetryMismatch,
    /// Runtime intent resources differ from the canonical capture resource set.
    IntentResourceMismatch,
    /// A decision binding could not be represented canonically.
    Encoding(CanonicalError),
}

impl std::fmt::Display for BootstrapRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ForeignCaptureInstitution => "capture registry belongs to another institution",
            Self::ForeignCaptureWorkspace => "capture registry belongs to another workspace",
            Self::CaptureNotAdmitted => "selected capture was not admitted",
            Self::UnexpectedDelegationKind => "authority was not admitted as a delegation",
            Self::ForeignDelegationInstitution => "delegation belongs to another institution",
            Self::ForeignDelegationWorkspace => "delegation belongs to another workspace",
            Self::DelegationSignerMismatch => "delegation signer differs from its issuer",
            Self::DelegationIssuerNotOwner => "delegation issuer is not the installed owner",
            Self::IndirectDelegation => "bootstrap reconnaissance requires a direct owner grant",
            Self::SelfDelegation => "bootstrap reconnaissance delegation is self-issued",
            Self::PrincipalMismatch => {
                "capture, scope, delegation, and requester principals differ"
            }
            Self::CaptureDelegationMismatch => "capture, scope, and authority delegation differ",
            Self::DelegatedActionMismatch => "delegation does not carry the exact bootstrap action",
            Self::DelegatedResourceMismatch => {
                "delegation does not carry the exact capture resources"
            }
            Self::DelegatedEffectMismatch => {
                "delegation does not carry the sole external-system read effect"
            }
            Self::DelegatedAudienceMismatch => {
                "delegation audience is not the installed institution"
            }
            Self::UnboundedDelegationBudget => "delegation resource budget is not finite",
            Self::ReconnaissanceAuthority(_) => "reconnaissance authority is invalid",
            Self::ScopeOutlivesDelegation => "reconnaissance scope outlives its delegation",
            Self::CaptureAfterExpiry => "capture time is outside delegated authority",
            Self::SourceScopeMismatch => "scope does not name exactly the captured source",
            Self::AdapterScopeMismatch => "scope does not name exactly the capture adapter",
            Self::OperationNameMismatch => "operation name is not the built-in capture operation",
            Self::OperationActionMismatch => "operation action is not exact reconnaissance",
            Self::OperationEffectMismatch => "operation effect is not an external-system read",
            Self::OperationDataMismatch => "operation data classes differ from delegated classes",
            Self::OperationEvidenceMismatch => "operation capture evidence obligation is not exact",
            Self::OperationRequiresExecutionAssignment => {
                "bootstrap capture cannot request an execution assignment"
            }
            Self::OperationRetryMismatch => "bootstrap capture must be non-retryable",
            Self::IntentResourceMismatch => "intent resources differ from the signed capture",
            Self::Encoding(_) => "bootstrap decision binding could not be encoded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BootstrapRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReconnaissanceAuthority(source) => Some(source),
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}
