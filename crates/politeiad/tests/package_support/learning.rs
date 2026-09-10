//! Signed public-process learning requests for the commissioning-package test.
//!
//! These helpers construct only transport documents. The caller must submit
//! every document through the installed daemon and retain returned identities;
//! this module never opens storage or invokes a service directly.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use politeia_core::{
    CommissioningRecordId, Delegation, Digest, Effect, EvidenceId, PrincipalId, ResourceBudget,
    RuntimeGenerationId,
    canonical::to_canonical_bytes,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assessment::AssessmentRelation;
use politeiad::{
    learning::{
        CONTEXT_READ_EFFECT, CapabilityRequest, ContextRequest, FeedbackRequest,
        context_source_resource, context_workspace_resource,
    },
    service_learning::{
        LearningDisclosureIngress, LearningIngress, LearningRequest, durable_signed_wire_digest,
    },
    service_operation::OperationSubmission,
};

use super::{CandidateDocuments, CaptureDocuments, LearningSourceDocuments, ReferenceFixture};

/// Primary active-context wire and the exact input binding for a separately
/// signed operational submission.
pub(crate) struct ActiveContextDraft {
    request: SignedAdmissionWire<LearningDisclosureIngress<ContextRequest>>,
    input_digest: Digest,
    resources: BTreeSet<String>,
}

impl ActiveContextDraft {
    /// Canonical input binding that the separately signed operation must carry.
    pub(crate) fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    /// Exact source and workspace resource axes that the operation must carry.
    pub(crate) fn resources(&self) -> &BTreeSet<String> {
        &self.resources
    }

    /// The only replay key the separately signed operation may carry.
    pub(crate) fn idempotency_key(&self) -> String {
        format!("learning:{}", self.request.payload.id.0)
    }

    /// Place the separately signed operational material outside the primary
    /// request wire, avoiding a recursive request digest.
    pub(crate) fn document(self, active_submission: OperationSubmission) -> serde_json::Value {
        serde_json::json!({
            "kind": "learning",
            "request": LearningRequest::CompileContext {
                request: self.request,
                active_submission: Some(active_submission),
            },
        })
    }
}

/// Primary active-discovery wire and its separately signed operation binding.
pub(crate) struct ActiveDiscoveryDraft {
    request: SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
    input_digest: Digest,
    resources: BTreeSet<String>,
}

impl ActiveDiscoveryDraft {
    /// Canonical input binding that the separately signed operation must carry.
    pub(crate) fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    /// Exact workspace resource axis that the discovery operation must carry.
    pub(crate) fn resources(&self) -> &BTreeSet<String> {
        &self.resources
    }

    /// The only replay key the separately signed operation may carry.
    pub(crate) fn idempotency_key(&self) -> String {
        format!("learning:{}", self.request.payload.id.0)
    }

    /// Place the separately signed operational material outside the primary
    /// request wire, avoiding a recursive request digest.
    pub(crate) fn document(self, active_submission: OperationSubmission) -> serde_json::Value {
        serde_json::json!({
            "kind": "learning",
            "request": LearningRequest::DiscoverCapabilities {
                request: self.request,
                active_submission: Some(active_submission),
            },
        })
    }
}

/// Known feedback record identity and its signed daemon request.
pub(crate) struct FeedbackDocuments {
    /// Identity used by the later owner correction request.
    pub(crate) id: CommissioningRecordId,
    /// Public daemon transport document.
    pub(crate) document: serde_json::Value,
}

impl ReferenceFixture {
    /// Sign an active context request before constructing its operation intent.
    ///
    /// `requester` and `requester_key` must be an installed learning-context
    /// principal. The caller first passes [`ActiveContextDraft::input_digest`]
    /// and [`ActiveContextDraft::resources`] to the operational fixture, then
    /// attaches its resulting separately signed submission with `document`.
    pub(crate) fn active_context_draft(
        &self,
        requester: PrincipalId,
        requester_key: &SigningKey,
        delegation: &Delegation,
        generation: RuntimeGenerationId,
        source: &LearningSourceDocuments,
        candidate: &CandidateDocuments,
    ) -> ActiveContextDraft {
        let resources = BTreeSet::from([
            context_workspace_resource(&self.host_trust.workspace.id),
            context_source_resource(&self.host_trust.workspace.id, &source.source),
        ]);
        let request = LearningDisclosureIngress {
            id: CommissioningRecordId::new(),
            requester: requester.clone(),
            delegation: delegation.id.clone(),
            budget: delegation.budget.clone(),
            input: ContextRequest {
                institution: self.host_trust.workspace.institution.clone(),
                workspace: self.host_trust.workspace.id.clone(),
                generation,
                compiler_version: "learning-v1".to_owned(),
                audience: "commissioning".to_owned(),
                sink: "package-acceptance".to_owned(),
                trust_domain: self.host_trust.workspace.trust_domain.clone(),
                limit: 1,
            },
        };
        let request = SignedAdmissionWire::sign(
            AdmissionKind::LearningContext,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            requester,
            request,
            requester_key,
        )
        .expect("active requester signs primary context wire");
        let population = Digest::blake3(
            &to_canonical_bytes(&vec![(
                &source.source,
                &candidate.candidate.payload.proposition,
            )])
            .expect("selected context population canonically encodes"),
        );
        let input_digest = disclosure_input_digest(&request, &population);
        ActiveContextDraft {
            request,
            input_digest,
            resources,
        }
    }

    /// Sign an active discovery request before constructing its operation intent.
    ///
    /// `population` must be the canonical digest of the exact active registry
    /// capability inventory that the operational fixture will publish.
    pub(crate) fn active_discovery_draft(
        &self,
        requester: PrincipalId,
        requester_key: &SigningKey,
        delegation: &Delegation,
        generation: RuntimeGenerationId,
        population: Digest,
    ) -> ActiveDiscoveryDraft {
        let resources = BTreeSet::from([context_workspace_resource(&self.host_trust.workspace.id)]);
        let request = LearningDisclosureIngress {
            id: CommissioningRecordId::new(),
            requester: requester.clone(),
            delegation: delegation.id.clone(),
            budget: delegation.budget.clone(),
            input: CapabilityRequest {
                institution: self.host_trust.workspace.institution.clone(),
                workspace: self.host_trust.workspace.id.clone(),
                generation,
            },
        };
        let request = SignedAdmissionWire::sign(
            AdmissionKind::LearningDiscovery,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            requester,
            request,
            requester_key,
        )
        .expect("active requester signs primary discovery wire");
        let input_digest = disclosure_input_digest(&request, &population);
        ActiveDiscoveryDraft {
            request,
            input_digest,
            resources,
        }
    }

    /// Construct signed feedback over exact context provenance.
    ///
    /// The feedback remains inert until the daemon validates its current
    /// authority and source provenance, then appends the proposal under the
    /// returned `id` for a later owner correction.
    pub(crate) fn feedback_documents(
        &self,
        requester: PrincipalId,
        requester_key: &SigningKey,
        delegation: &Delegation,
        generation: RuntimeGenerationId,
        source: &LearningSourceDocuments,
        capture: &CaptureDocuments,
        feedback_digest: Digest,
    ) -> FeedbackDocuments {
        let id = CommissioningRecordId::new();
        let request = LearningIngress {
            id: id.clone(),
            requester: requester.clone(),
            delegation: delegation.id.clone(),
            input: FeedbackRequest {
                institution: self.host_trust.workspace.institution.clone(),
                workspace: self.host_trust.workspace.id.clone(),
                generation,
                source: source.source.clone(),
                observation: capture.observation.id.clone(),
                evidence: capture.evidence.clone(),
                feedback_digest,
            },
        };
        let request = SignedAdmissionWire::sign(
            AdmissionKind::LearningFeedback,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            requester,
            request,
            requester_key,
        )
        .expect("feedback requester signs exact provenance request");
        FeedbackDocuments {
            id,
            document: serde_json::json!({
                "kind": "learning",
                "request": LearningRequest::RecordFeedback { request },
            }),
        }
    }

    /// Construct an owner-authenticated correction-view request over a
    /// daemon-retained feedback record and exact assessment relation.
    pub(crate) fn approved_correction_document(
        &self,
        owner_correction: &Delegation,
        feedback: CommissioningRecordId,
        subject: Digest,
        relation: AssessmentRelation,
    ) -> serde_json::Value {
        assert_eq!(relation.authority, self.identities.owner);
        assert_eq!(relation.authority_delegation, owner_correction.id);
        let request = LearningIngress {
            id: CommissioningRecordId::new(),
            requester: self.identities.owner.clone(),
            delegation: owner_correction.id.clone(),
            input: politeiad::service_learning::CorrectionViewRequest {
                subject,
                feedback,
                relations: vec![relation],
            },
        };
        let request = SignedAdmissionWire::sign(
            AdmissionKind::LearningCorrection,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            request,
            self.identities.owner_key(),
        )
        .expect("owner signs correction after feedback");
        serde_json::json!({
            "kind": "learning",
            "request": LearningRequest::CorrectionView { request },
        })
    }
}

fn disclosure_input_digest<T: serde::Serialize>(
    request: &SignedAdmissionWire<LearningDisclosureIngress<T>>,
    population: &Digest,
) -> Digest {
    let request_digest = durable_signed_wire_digest(request)
        .expect("primary signed learning wire canonically digests");
    Digest::blake3(
        &to_canonical_bytes(&(request_digest, population))
            .expect("primary wire and selected population canonically encode"),
    )
}

/// Exact finite context budget expected by active learning delegations.
///
/// The operational fixture may reuse this to construct a requester grant;
/// keeping it here ensures every request copies the same bounded budget axis.
pub(crate) fn active_learning_budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(30_000),
        cpu_ms: Some(10_000),
        memory_bytes: Some(32 * 1024 * 1024),
        io_bytes: Some(1024 * 1024),
        network_bytes: Some(0),
        external_cost_microunits: Some(0),
    }
}

/// Exact context effect used by active context, discovery, and feedback grants.
pub(crate) fn active_learning_effects() -> BTreeSet<Effect> {
    BTreeSet::from([CONTEXT_READ_EFFECT])
}
