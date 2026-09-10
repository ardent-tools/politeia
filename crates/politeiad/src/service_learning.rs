//! Authenticated service handlers for the institutional learning loop.
//!
//! The pure projections in [`crate::learning`] never see transport documents.
//! This module admits the exact signed requester envelopes, recovers only
//! durable signed knowledge, and commits feedback/proposals without making a
//! caller-authored fact or relation authoritative.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::{
    AdapterId, CommissioningRecordId, DataClass, DelegationId, Digest, EvidenceId, ObservationId,
    PrincipalId, SourceCaptureId,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    knowledge::{
        FactApprovalRequest, SourceCaptureRequest, TrustedCandidateClaimRegistry,
        TrustedObservationRegistry, TrustedSourceCaptureRegistry, approve_claim,
    },
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assessment::AssessmentRelation;
use politeia_storage::{ScopedCommit, SignedRecord, StateMutation, WorkspaceSnapshot};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CoordinatorError, OperationResult,
    learning::{
        ActiveCapabilities, CapabilityRequest, CompiledContext, ContextRequest, ContextSource,
        FeedbackRequest, KnowledgeCurrency, LearningSnapshot,
    },
    service::{PoliteiadService, refusal, signed_wire_record, storage_refusal},
};

/// A signed request that proves a durable delegation holder requested one exact
/// learning operation. It is raw until the handler selects its admission kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningIngress<T> {
    /// Stable append-only request identity.
    pub id: CommissioningRecordId,
    /// Principal that signs and requests this exact operation.
    pub requester: PrincipalId,
    /// Durable delegation the requester claims to hold.
    pub delegation: DelegationId,
    /// Exact inert operation input.
    pub input: T,
}

/// Owner-pinned content and eligibility metadata for one approved fact.
///
/// The signed binding carries the institution-owned content bytes only so the
/// daemon can verify `content_digest == proposition` before it creates a
/// context reference. It never returns those bytes through this API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSourceRequest {
    /// Stable source identity used in context grants and deterministic order.
    pub id: EvidenceId,
    /// Approved fact this source may hydrate.
    pub claim: politeia_core::ClaimId,
    /// Digest of the durable signed fact approval wire for `claim`.
    pub approval_digest: Digest,
    /// Exact approved subject.
    pub subject: Digest,
    /// Exact approved proposition and digest of `content`.
    pub proposition: Digest,
    /// Institution-owned bytes bound to the approved proposition.
    #[schemars(length(min = 1))]
    pub content: Vec<u8>,
    /// Evidence identities retained as context provenance.
    pub evidence: BTreeSet<EvidenceId>,
    /// Observation identities retained as context provenance.
    pub observations: BTreeSet<ObservationId>,
    /// Capture identities from which the observations derive.
    pub captures: BTreeSet<SourceCaptureId>,
    /// Adapter that produced the observations.
    pub adapter: AdapterId,
    /// Canonical knowledge outranks preserved archive in the pure projection.
    pub currency: KnowledgeCurrency,
    /// Data classes eligible for a caller's live delegation.
    pub data_classes: BTreeSet<DataClass>,
    /// Institutional audiences that may receive this content.
    pub audiences: BTreeSet<String>,
    /// Named sinks eligible to receive this content.
    pub sinks: BTreeSet<String>,
    /// Trust domain in which the content may be compiled.
    pub trust_domain: politeia_core::institution::TrustDomainId,
    /// Deterministic relevance after every eligibility check.
    pub relevance: u32,
}

/// A correction view request. Relations remain append-only evidence statements;
/// this handler does not make the request itself an approved fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrectionViewRequest {
    /// Subject over which the canonical assessment projection is requested.
    pub subject: Digest,
    /// Exact candidate correction/supersession relations.
    pub relations: Vec<AssessmentRelation>,
}

/// Typed, inert learning documents accepted under `commissioning.learning`.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LearningRequest {
    /// Persist one owner-pinned approved content binding for later hydration.
    RegisterSource {
        /// Signed owner binding, admitted only as `LearningSource`.
        source: SignedAdmissionWire<LearningSourceRequest>,
    },
    /// Compile context from durable approved content only.
    CompileContext {
        /// Signed requester/delegation-bound request.
        request: SignedAdmissionWire<LearningIngress<ContextRequest>>,
    },
    /// Discover descriptive active-generation capabilities.
    DiscoverCapabilities {
        /// Signed requester/delegation-bound request.
        request: SignedAdmissionWire<LearningIngress<CapabilityRequest>>,
    },
    /// Record feedback as an inert, append-only correction proposal.
    RecordFeedback {
        /// Signed requester/delegation-bound feedback.
        request: SignedAdmissionWire<LearningIngress<FeedbackRequest>>,
    },
    /// Project evidence relations after signed requester/delegation admission.
    CorrectionView {
        /// Signed requester/delegation-bound relation input.
        request: SignedAdmissionWire<LearningIngress<CorrectionViewRequest>>,
    },
}

impl PoliteiadService {
    /// Dispatch one opaque learning document after transport has selected the
    /// commissioning boundary.
    pub(crate) async fn handle_learning(
        &self,
        value: Value,
    ) -> Result<OperationResult, CoordinatorError> {
        let request: LearningRequest = serde_json::from_value(value).map_err(|error| {
            CoordinatorError::Refused(format!("learning input is not typed JSON: {error}"))
        })?;
        match request {
            LearningRequest::RegisterSource { source } => self.register_source(source).await,
            LearningRequest::CompileContext { request } => self.compile_context(request).await,
            LearningRequest::DiscoverCapabilities { request } => {
                self.discover_capabilities(request).await
            }
            LearningRequest::RecordFeedback { request } => self.record_feedback(request).await,
            LearningRequest::CorrectionView { request } => self.correction_view(request).await,
        }
    }

    async fn register_source(
        &self,
        source: SignedAdmissionWire<LearningSourceRequest>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningSource, source.clone())
            .map_err(refusal)?;
        if admitted.signer() != &self.workspace().owner {
            return Err(CoordinatorError::Refused(
                "learning source must be signed by the installed owner".to_string(),
            ));
        }
        let durable = self.durable_snapshot().await?;
        validate_new_source(
            self.workspace(),
            self.anchors(),
            &durable,
            admitted.payload(),
        )?;
        self.commit_learning(
            &durable,
            "learning_source",
            signed_wire_record(&source)?,
            format!("learning_source:{}", admitted.payload().id.0),
            signed_wire_record(&source)?,
        )
        .await
    }

    async fn compile_context(
        &self,
        wire: SignedAdmissionWire<LearningIngress<ContextRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningContext, wire)
            .map_err(refusal)?;
        let delegation = self
            .live_requester(
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let durable = self.durable_snapshot().await?;
        let snapshot = self.learning_snapshot(&durable, &admitted.payload().input.generation)?;
        let result = crate::learning::compile_context(
            &snapshot,
            &admitted.payload().requester,
            delegation.payload(),
            &admitted.payload().input,
            self.now().await?,
        )
        .map_err(refusal)?;
        Ok(context_result(&result))
    }

    async fn discover_capabilities(
        &self,
        wire: SignedAdmissionWire<LearningIngress<CapabilityRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningDiscovery, wire)
            .map_err(refusal)?;
        let delegation = self
            .live_requester(
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let durable = self.durable_snapshot().await?;
        let snapshot = self.learning_snapshot(&durable, &admitted.payload().input.generation)?;
        let result = crate::learning::discover_capabilities(
            &snapshot,
            &admitted.payload().requester,
            delegation.payload(),
            &admitted.payload().input,
            self.now().await?,
        )
        .map_err(refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!(result),
            evidence_refs: Vec::new(),
        })
    }

    async fn record_feedback(
        &self,
        wire: SignedAdmissionWire<LearningIngress<FeedbackRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningFeedback, wire.clone())
            .map_err(refusal)?;
        let delegation = self
            .live_requester(
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let durable = self.durable_snapshot().await?;
        let snapshot = self.learning_snapshot(&durable, &admitted.payload().input.generation)?;
        let proposal = crate::learning::record_feedback(
            &snapshot,
            &admitted.payload().requester,
            delegation.payload(),
            &admitted.payload().input,
            self.now().await?,
        )
        .map_err(refusal)?;
        self.commit_learning(
            &durable,
            "learning_feedback",
            signed_wire_record(&wire)?,
            format!("learning_feedback:{}", admitted.payload().id.0),
            signed_wire_record(&wire)?,
        )
        .await
        .map(|mut outcome| {
            if let OperationResult::Coordinated { result, .. } = &mut outcome {
                *result = json!({"proposal": proposal, "committed": result});
            }
            outcome
        })
    }

    async fn correction_view(
        &self,
        wire: SignedAdmissionWire<LearningIngress<CorrectionViewRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningCorrection, wire)
            .map_err(refusal)?;
        let delegation = self
            .live_requester(
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        for relation in &admitted.payload().input.relations {
            if relation.authority != admitted.payload().requester
                || relation.authority_delegation != admitted.payload().delegation
            {
                return Err(CoordinatorError::Refused(
                    "correction relation must name the signed live requester and delegation"
                        .to_string(),
                ));
            }
        }
        let durable = self.durable_snapshot().await?;
        let evidence = durable_evidence(self.anchors(), &durable)?;
        let delegations = durable_delegations(
            self,
            &durable,
            &admitted.payload().requester,
            delegation.payload(),
        )?;
        let projection = crate::learning::correction_view(
            &admitted.payload().input.subject,
            &evidence,
            &admitted.payload().input.relations,
            &delegations,
        )
        .map_err(refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!(projection),
            evidence_refs: Vec::new(),
        })
    }

    async fn live_requester(
        &self,
        requester: &PrincipalId,
        delegation: &DelegationId,
    ) -> Result<politeia_core::trust::Admitted<politeia_core::Delegation>, CoordinatorError> {
        self.admit_live_delegation(delegation, requester).await
    }

    async fn now(&self) -> Result<Timestamp, CoordinatorError> {
        politeia_runtime::AuthorizationLedger::observed_at(
            &politeia_storage::PostgresAuthorizationLedger::new(
                self.storage().clone(),
                self.scope().clone(),
            ),
        )
        .await
        .map_err(|error| {
            CoordinatorError::Refused(format!(
                "durable authorization clock refused operation: {error}"
            ))
        })
    }

    async fn commit_learning(
        &self,
        durable: &WorkspaceSnapshot,
        kind: &str,
        transition: SignedRecord,
        state_key: String,
        state: SignedRecord,
    ) -> Result<OperationResult, CoordinatorError> {
        if durable.state.contains_key(&state_key) {
            return Err(CoordinatorError::Refused(
                "learning request identity was already committed".to_string(),
            ));
        }
        let receipt = self
            .storage()
            .commit(&ScopedCommit {
                scope: self.scope().clone(),
                expected_revision: durable.revision,
                model: durable.model.clone(),
                model_kind: kind.to_string(),
                transition,
                state: vec![StateMutation {
                    key: state_key,
                    value: state,
                }],
                evidence: Vec::new(),
                outbox: Vec::new(),
            })
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({"revision": receipt.revision, "transition": receipt.transition_digest}),
            evidence_refs: Vec::new(),
        })
    }

    fn learning_snapshot(
        &self,
        durable: &WorkspaceSnapshot,
        generation: &politeia_core::RuntimeGenerationId,
    ) -> Result<LearningSnapshot, CoordinatorError> {
        if durable.active_generation.as_ref() != Some(generation.digest()) {
            return Err(CoordinatorError::Refused(
                "requested learning generation is not durably active".to_string(),
            ));
        }
        Ok(LearningSnapshot {
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            generation: generation.clone(),
            trust_domain: self.workspace().trust_domain.clone(),
            compiler_version: "learning-v1".to_string(),
            sources: self.learning_sources(durable)?.into_values().collect(),
            capabilities: ActiveCapabilities::default(),
        })
    }

    fn learning_sources(
        &self,
        durable: &WorkspaceSnapshot,
    ) -> Result<BTreeMap<EvidenceId, ContextSource>, CoordinatorError> {
        let evidence = durable_evidence(self.anchors(), durable)?;
        let captures = durable_captures(self.anchors(), durable)?;
        let observations = durable_observations(
            self.workspace(),
            self.anchors(),
            &evidence,
            &captures,
            durable,
        )?;
        let candidates =
            durable_candidates(self.workspace(), self.anchors(), &observations, durable)?;
        let facts = durable_facts(
            self.workspace(),
            self.anchors(),
            &observations,
            &candidates,
            durable,
        )?;
        let mut sources = BTreeMap::new();
        for (key, payload) in &durable.state {
            if !key.starts_with("learning_source:") {
                continue;
            }
            let wire: SignedAdmissionWire<LearningSourceRequest> =
                serde_json::from_slice(&payload.bytes).map_err(|_| {
                    CoordinatorError::Refused(
                        "durable learning source is not a signed source wire".to_string(),
                    )
                })?;
            if wire.kind != AdmissionKind::LearningSource {
                continue;
            }
            let admitted = self
                .anchors()
                .admit_expected(AdmissionKind::LearningSource, wire)
                .map_err(refusal)?;
            let source = admitted.payload();
            if admitted.signer() != &self.workspace().owner
                || source.trust_domain != self.workspace().trust_domain
                || Digest::blake3(&source.content) != source.proposition
            {
                return Err(CoordinatorError::Refused(
                    "durable learning source is not owner-pinned approved content".to_string(),
                ));
            }
            let approval = durable
                .state
                .get(&format!("fact_approval:{}", source.claim.0))
                .ok_or_else(|| {
                    CoordinatorError::Refused(
                        "learning source approval is absent from durable state".to_string(),
                    )
                })?;
            if approval.digest != source.approval_digest {
                return Err(CoordinatorError::Refused(
                    "learning source approval digest differs from durable approval".to_string(),
                ));
            }
            let fact = facts.get(&source.claim).ok_or_else(|| {
                CoordinatorError::Refused(
                    "learning source has no durable approved fact".to_string(),
                )
            })?;
            if fact.subject() != &source.subject || fact.proposition() != &source.proposition {
                return Err(CoordinatorError::Refused(
                    "learning source differs from durable approved fact".to_string(),
                ));
            }
            if source
                .evidence
                .iter()
                .any(|id| evidence.resolve(id).is_none())
                || source
                    .observations
                    .iter()
                    .any(|id| observations.resolve(id).is_none())
                || source
                    .captures
                    .iter()
                    .any(|id| captures.resolve(id).is_none())
            {
                return Err(CoordinatorError::Refused(
                    "learning source provenance is absent from durable admission".to_string(),
                ));
            }
            if sources
                .insert(
                    source.id.clone(),
                    ContextSource {
                        id: source.id.clone(),
                        fact: fact.clone(),
                        observations: source.observations.clone(),
                        evidence: source.evidence.clone(),
                        adapter: source.adapter.clone(),
                        currency: source.currency,
                        data_classes: source.data_classes.clone(),
                        audiences: source.audiences.clone(),
                        sinks: source.sinks.clone(),
                        trust_domain: source.trust_domain.clone(),
                        relevance: source.relevance,
                    },
                )
                .is_some()
            {
                return Err(CoordinatorError::Refused(
                    "durable learning source identity is ambiguous".to_string(),
                ));
            }
        }
        Ok(sources)
    }
}

fn validate_new_source(
    workspace: &politeia_core::institution::InstitutionWorkspace,
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
    source: &LearningSourceRequest,
) -> Result<(), CoordinatorError> {
    if source.trust_domain != workspace.trust_domain
        || Digest::blake3(&source.content) != source.proposition
    {
        return Err(CoordinatorError::Refused(
            "learning source content is not bound to its exact approved proposition".to_string(),
        ));
    }
    let approval = durable
        .state
        .get(&format!("fact_approval:{}", source.claim.0))
        .ok_or_else(|| {
            CoordinatorError::Refused(
                "learning source approval is absent from durable state".to_string(),
            )
        })?;
    if approval.digest != source.approval_digest {
        return Err(CoordinatorError::Refused(
            "learning source approval digest differs from durable approval".to_string(),
        ));
    }
    let evidence = durable_evidence(anchors, durable)?;
    let captures = durable_captures(anchors, durable)?;
    let observations = durable_observations(workspace, anchors, &evidence, &captures, durable)?;
    let candidates = durable_candidates(workspace, anchors, &observations, durable)?;
    let facts = durable_facts(workspace, anchors, &observations, &candidates, durable)?;
    let fact = facts.get(&source.claim).ok_or_else(|| {
        CoordinatorError::Refused("learning source has no durable approved fact".to_string())
    })?;
    if fact.subject() != &source.subject
        || fact.proposition() != &source.proposition
        || source
            .evidence
            .iter()
            .any(|id| evidence.resolve(id).is_none())
        || source
            .observations
            .iter()
            .any(|id| observations.resolve(id).is_none())
        || source
            .captures
            .iter()
            .any(|id| captures.resolve(id).is_none())
    {
        return Err(CoordinatorError::Refused(
            "learning source does not resolve exact durable approved provenance".to_string(),
        ));
    }
    Ok(())
}

fn context_result(result: &CompiledContext) -> OperationResult {
    OperationResult::Coordinated {
        result: json!(result),
        evidence_refs: Vec::new(),
    }
}

fn durable_evidence(
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
) -> Result<TrustedEvidenceRegistry, CoordinatorError> {
    let mut wires = Vec::new();
    for record in durable.evidence.values() {
        let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(record.payload())
            .map_err(|_| {
            CoordinatorError::Refused("durable evidence is not a signed evidence wire".to_string())
        })?;
        if wire.signer != *record.signer() || wire.signature != record.signature() {
            return Err(CoordinatorError::Refused(
                "durable evidence record and wire binding differ".to_string(),
            ));
        }
        wires.push(wire);
    }
    TrustedEvidenceRegistry::admit_signed(anchors, wires).map_err(refusal)
}

fn signed_state_wires<T: serde::de::DeserializeOwned>(
    durable: &WorkspaceSnapshot,
    prefix: &str,
    expected: AdmissionKind,
) -> Result<Vec<SignedAdmissionWire<T>>, CoordinatorError> {
    durable
        .state
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(_, payload)| {
            let wire: SignedAdmissionWire<T> =
                serde_json::from_slice(&payload.bytes).map_err(|_| {
                    CoordinatorError::Refused(
                        "durable learning state is not the expected signed wire".to_string(),
                    )
                })?;
            if wire.kind != expected {
                return Err(CoordinatorError::Refused(
                    "durable learning state has the wrong admission kind".to_string(),
                ));
            }
            Ok(wire)
        })
        .collect()
}

fn durable_captures(
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
) -> Result<TrustedSourceCaptureRegistry, CoordinatorError> {
    let wires = durable
        .state
        .values()
        .filter_map(|payload| {
            serde_json::from_slice::<SignedAdmissionWire<SourceCaptureRequest>>(&payload.bytes).ok()
        })
        .filter(|wire| wire.kind == AdmissionKind::SourceCapture)
        .collect::<Vec<_>>();
    TrustedSourceCaptureRegistry::admit_signed(anchors, wires).map_err(refusal)
}

fn durable_observations(
    workspace: &politeia_core::institution::InstitutionWorkspace,
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    evidence: &TrustedEvidenceRegistry,
    captures: &TrustedSourceCaptureRegistry,
    durable: &WorkspaceSnapshot,
) -> Result<TrustedObservationRegistry, CoordinatorError> {
    let wires = signed_state_wires(durable, "observation:", AdmissionKind::Observation)?;
    TrustedObservationRegistry::admit_signed(workspace, anchors, evidence, captures, wires)
        .map_err(refusal)
}

fn durable_candidates(
    workspace: &politeia_core::institution::InstitutionWorkspace,
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    observations: &TrustedObservationRegistry,
    durable: &WorkspaceSnapshot,
) -> Result<TrustedCandidateClaimRegistry, CoordinatorError> {
    let wires = signed_state_wires(durable, "candidate_claim:", AdmissionKind::CandidateClaim)?;
    TrustedCandidateClaimRegistry::admit_signed(workspace, anchors, observations, wires)
        .map_err(refusal)
}

fn durable_facts(
    workspace: &politeia_core::institution::InstitutionWorkspace,
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    observations: &TrustedObservationRegistry,
    candidates: &TrustedCandidateClaimRegistry,
    durable: &WorkspaceSnapshot,
) -> Result<
    BTreeMap<politeia_core::ClaimId, politeia_core::knowledge::ApprovedFact>,
    CoordinatorError,
> {
    let mut facts = BTreeMap::new();
    for (key, payload) in &durable.state {
        if !key.starts_with("fact_approval:") {
            continue;
        }
        let wire: SignedAdmissionWire<FactApprovalRequest> = serde_json::from_slice(&payload.bytes)
            .map_err(|_| {
                CoordinatorError::Refused(
                    "durable approval is not a signed approval wire".to_string(),
                )
            })?;
        if wire.kind != AdmissionKind::FactApproval {
            return Err(CoordinatorError::Refused(
                "durable approval has the wrong admission kind".to_string(),
            ));
        }
        let fact =
            approve_claim(workspace, observations, anchors, candidates, wire).map_err(refusal)?;
        if facts.insert(fact.claim().clone(), fact).is_some() {
            return Err(CoordinatorError::Refused(
                "durable fact approval identity is ambiguous".to_string(),
            ));
        }
    }
    Ok(facts)
}

fn durable_delegations(
    service: &PoliteiadService,
    durable: &WorkspaceSnapshot,
    requester: &PrincipalId,
    requester_delegation: &politeia_core::Delegation,
) -> Result<BTreeMap<DelegationId, politeia_core::Delegation>, CoordinatorError> {
    let mut result = BTreeMap::new();
    for (id, persisted) in &durable.delegations {
        if persisted.revoked {
            continue;
        }
        let admitted = service
            .anchors()
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        if admitted.payload().id != *id {
            return Err(CoordinatorError::Refused(
                "durable delegation identity differs from its wire".to_string(),
            ));
        }
        result.insert(id.clone(), admitted.into_payload());
    }
    result.insert(
        requester_delegation.id.clone(),
        requester_delegation.clone(),
    );
    if !result.values().any(|grant| grant.subject == *requester) {
        return Err(CoordinatorError::Refused(
            "no durable delegation belongs to correction requester".to_string(),
        ));
    }
    Ok(result)
}
