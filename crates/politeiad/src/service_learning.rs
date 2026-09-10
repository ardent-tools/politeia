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
    PrincipalId, ResourceBudget, SourceCaptureId,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    knowledge::{
        FactApprovalRequest, SourceCaptureRequest, TrustedCandidateClaimRegistry,
        TrustedObservationRegistry, TrustedSourceCaptureRegistry, approve_claim,
    },
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assessment::{AssessmentRelation, Projection};
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

/// A signed request whose result can disclose institutional context.
///
/// Unlike feedback, a disclosure reserves a finite durable budget and replay
/// key before its effect port may return any selected bytes or capability
/// identities.  Keeping this distinct from [`LearningIngress`] makes a
/// missing budget unrepresentable at the protected read boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningDisclosureIngress<T> {
    /// Stable request identity used as the durable replay key.
    pub id: CommissioningRecordId,
    /// Principal that signs and requests this exact disclosure.
    pub requester: PrincipalId,
    /// Durable delegation the requester claims to hold.
    pub delegation: DelegationId,
    /// Finite maximum consumption reserved before disclosure.
    pub budget: ResourceBudget,
    /// Exact inert context or discovery input.
    pub input: T,
}

/// Owner-pinned content and eligibility metadata for one approved fact.
///
/// The signed binding carries the institution-owned content bytes only so the
/// daemon can verify `content_digest == proposition` before it creates a
/// context reference. After delegation, audience, sink, data-class, and trust
/// checks select it, the coordinator returns those exact approved bytes.
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
    /// Earlier persisted feedback whose inert proposal this relation resolves.
    pub feedback: CommissioningRecordId,
    /// Exact candidate correction/supersession relations.
    pub relations: Vec<AssessmentRelation>,
}

/// Typed, inert learning documents accepted under `commissioning.learning`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
        request: SignedAdmissionWire<LearningDisclosureIngress<ContextRequest>>,
    },
    /// Discover descriptive active-generation capabilities.
    DiscoverCapabilities {
        /// Signed requester/delegation-bound request.
        request: SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
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

/// Return the exact digest PostgreSQL stores for a signed wire.
///
/// Source bindings use this digest to name their fact approval. It is BLAKE3
/// over the canonical JSON record, so callers must use this helper instead of
/// hashing ordinary serializer output.
pub fn durable_signed_wire_digest<T: Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<Digest, CoordinatorError> {
    Ok(signed_wire_record(wire)?.digest().clone())
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
            None,
        )
        .await
    }

    async fn compile_context(
        &self,
        wire: SignedAdmissionWire<LearningDisclosureIngress<ContextRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningContext, wire)
            .map_err(refusal)?;
        require_disclosure_requester_signer(&admitted)?;
        require_finite_disclosure_budget(&admitted)?;
        let durable = self.durable_snapshot().await?;
        let authority = self
            .live_requester_chain(
                &durable,
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let delegation = delegation_leaf(&authority)?;
        let snapshot = self
            .learning_snapshot(&durable, &admitted.payload().input.generation)
            .await?;
        let result = crate::learning::compile_context(
            &snapshot,
            &admitted.payload().requester,
            delegation.payload(),
            &admitted.payload().input,
            self.now().await?,
        )
        .map_err(refusal)?;
        self.hydrate_context(&durable, &result)
    }

    async fn discover_capabilities(
        &self,
        wire: SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningDiscovery, wire)
            .map_err(refusal)?;
        require_disclosure_requester_signer(&admitted)?;
        require_finite_disclosure_budget(&admitted)?;
        let durable = self.durable_snapshot().await?;
        let authority = self
            .live_requester_chain(
                &durable,
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let delegation = delegation_leaf(&authority)?;
        let snapshot = self
            .learning_snapshot(&durable, &admitted.payload().input.generation)
            .await?;
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
        require_requester_signer(&admitted)?;
        let durable = self.durable_snapshot().await?;
        let authority = self
            .live_requester_chain(
                &durable,
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let delegation = delegation_leaf(&authority)?;
        let snapshot = self
            .learning_snapshot(&durable, &admitted.payload().input.generation)
            .await?;
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
            Some(&authority),
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
            .admit_expected(AdmissionKind::LearningCorrection, wire.clone())
            .map_err(refusal)?;
        require_requester_signer(&admitted)?;
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
        let authority = self
            .live_requester_chain(
                &durable,
                &admitted.payload().requester,
                &admitted.payload().delegation,
            )
            .await?;
        let delegation = delegation_leaf(&authority)?;
        let feedback =
            durable_feedback(self.anchors(), &durable, &admitted.payload().input.feedback)?;
        if !admitted.payload().input.relations.iter().any(|relation| {
            relation.prior == feedback.payload().input.source
                || relation.successor == feedback.payload().input.source
        }) {
            return Err(CoordinatorError::Refused(
                "correction relation does not resolve the persisted feedback source".to_string(),
            ));
        }
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
        self.commit_learning(
            &durable,
            "learning_correction",
            signed_wire_record(&wire)?,
            format!("learning_correction:{}", admitted.payload().id.0),
            signed_wire_record(&wire)?,
            Some(&authority),
        )
        .await
        .map(|mut outcome| {
            if let OperationResult::Coordinated { result, .. } = &mut outcome {
                *result = json!({"projection": projection, "committed": result});
            }
            outcome
        })
    }

    async fn live_requester(
        &self,
        requester: &PrincipalId,
        delegation: &DelegationId,
    ) -> Result<politeia_core::trust::Admitted<politeia_core::Delegation>, CoordinatorError> {
        self.admit_live_delegation(delegation, requester).await
    }

    /// Recover the exact root-to-leaf grants that an authorized commit or
    /// dispatcher reservation must retain.  The leaf is first recovered by
    /// the service's only live-delegation boundary, which validates the whole
    /// attenuation chain.  We then re-admit each immutable durable ancestor
    /// from the same snapshot used to derive the learning projection.
    ///
    /// The durable commit/ledger is still the linearization point: it locks
    /// and rechecks this exact chain before a mutation or protected disclosure
    /// can proceed.  This reconstruction supplies the dispatcher with every
    /// budget scope rather than incorrectly treating the leaf as ambient
    /// authority.
    async fn live_requester_chain(
        &self,
        durable: &WorkspaceSnapshot,
        requester: &PrincipalId,
        delegation_id: &DelegationId,
    ) -> Result<Vec<politeia_core::trust::Admitted<politeia_core::Delegation>>, CoordinatorError>
    {
        let leaf = self.live_requester(requester, delegation_id).await?;
        let mut reverse = vec![leaf];
        while let Some(parent_id) = reverse
            .last()
            .and_then(|grant| grant.payload().parent.clone())
        {
            let persisted = durable.delegations.get(&parent_id).ok_or_else(|| {
                CoordinatorError::Refused(
                    "delegation parent is not durably admitted for learning".to_string(),
                )
            })?;
            if persisted.revoked {
                return Err(CoordinatorError::Refused(
                    "delegation parent is revoked for learning".to_string(),
                ));
            }
            let parent = self
                .anchors()
                .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
                .map_err(refusal)?;
            if parent.payload().id != parent_id {
                return Err(CoordinatorError::Refused(
                    "durable delegation parent identity differs from its signed wire".to_string(),
                ));
            }
            reverse.push(parent);
        }
        reverse.reverse();
        Ok(reverse)
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
        authority: Option<&[politeia_core::trust::Admitted<politeia_core::Delegation>]>,
    ) -> Result<OperationResult, CoordinatorError> {
        if durable.state.contains_key(&state_key) {
            return Err(CoordinatorError::Refused(
                "learning request identity was already committed".to_string(),
            ));
        }
        let commit = ScopedCommit {
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
        };
        let receipt = match authority {
            Some(chain) => self.storage().commit_authorized(&commit, chain).await,
            None => self.storage().commit(&commit).await,
        }
        .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({"revision": receipt.revision, "transition": receipt.transition_digest}),
            evidence_refs: Vec::new(),
        })
    }

    fn hydrate_context(
        &self,
        durable: &WorkspaceSnapshot,
        context: &CompiledContext,
    ) -> Result<OperationResult, CoordinatorError> {
        let mut bytes = BTreeMap::new();
        for item in &context.items {
            let payload = durable
                .state
                .get(&format!("learning_source:{}", item.source.0))
                .ok_or_else(|| {
                    CoordinatorError::Refused(
                        "selected context source is absent from durable state".to_string(),
                    )
                })?;
            let wire: SignedAdmissionWire<LearningSourceRequest> =
                serde_json::from_slice(&payload.bytes).map_err(|_| {
                    CoordinatorError::Refused(
                        "selected context source is not a signed source wire".to_string(),
                    )
                })?;
            let admitted = self
                .anchors()
                .admit_expected(AdmissionKind::LearningSource, wire)
                .map_err(refusal)?;
            let source = admitted.payload();
            if admitted.signer() != &self.workspace().owner
                || source.id != item.source
                || source.claim != item.content.claim
                || source.subject != item.content.subject
                || source.proposition != item.content.proposition
                || Digest::blake3(&source.content) != source.proposition
            {
                return Err(CoordinatorError::Refused(
                    "selected context content differs from its durable approved reference"
                        .to_string(),
                ));
            }
            bytes.insert(source.id.clone(), source.content.clone());
        }
        Ok(OperationResult::Coordinated {
            result: json!({"context": context, "content": bytes}),
            evidence_refs: context
                .items
                .iter()
                .flat_map(|item| item.evidence.iter().map(|id| id.0.to_string()))
                .collect(),
        })
    }

    async fn learning_snapshot(
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
            sources: self
                .learning_sources(durable)
                .await?
                .into_values()
                .collect(),
            capabilities: ActiveCapabilities::default(),
        })
    }

    async fn learning_sources(
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
        let corrections = durable_corrections(self, durable).await?;
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
                || !source.evidence.contains(&source.id)
            {
                return Err(CoordinatorError::Refused(
                    "learning source provenance is absent from durable admission".to_string(),
                ));
            }
            if !source_survives_corrections(source, &evidence, &corrections)? {
                continue;
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

struct DurableCorrections {
    relations: Vec<AssessmentRelation>,
    delegations: BTreeMap<DelegationId, politeia_core::Delegation>,
}

async fn durable_corrections(
    service: &PoliteiadService,
    durable: &WorkspaceSnapshot,
) -> Result<DurableCorrections, CoordinatorError> {
    let mut relations = Vec::new();
    let mut delegations = BTreeMap::new();
    for (key, payload) in &durable.state {
        if !key.starts_with("learning_correction:") {
            continue;
        }
        let wire: SignedAdmissionWire<LearningIngress<CorrectionViewRequest>> =
            serde_json::from_slice(&payload.bytes).map_err(|_| {
                CoordinatorError::Refused(
                    "durable correction is not a signed correction request".to_string(),
                )
            })?;
        let admitted = service
            .anchors()
            .admit_expected(AdmissionKind::LearningCorrection, wire)
            .map_err(refusal)?;
        require_requester_signer(&admitted)?;
        let feedback = durable_feedback(
            service.anchors(),
            durable,
            &admitted.payload().input.feedback,
        )?;
        if !admitted.payload().input.relations.iter().any(|relation| {
            relation.prior == feedback.payload().input.source
                || relation.successor == feedback.payload().input.source
        }) {
            return Err(CoordinatorError::Refused(
                "durable correction does not resolve its persisted feedback source".to_string(),
            ));
        }
        let delegation = service
            .admit_live_delegation(
                &admitted.payload().delegation,
                &admitted.payload().requester,
            )
            .await?;
        for relation in &admitted.payload().input.relations {
            if relation.authority != admitted.payload().requester
                || relation.authority_delegation != admitted.payload().delegation
                || relation.authority_delegation != delegation.payload().id
            {
                return Err(CoordinatorError::Refused(
                    "durable correction relation differs from its signed live authority"
                        .to_string(),
                ));
            }
            relations.push(relation.clone());
        }
        delegations.insert(delegation.payload().id.clone(), delegation.into_payload());
    }
    Ok(DurableCorrections {
        relations,
        delegations,
    })
}

fn source_survives_corrections(
    source: &LearningSourceRequest,
    evidence: &TrustedEvidenceRegistry,
    corrections: &DurableCorrections,
) -> Result<bool, CoordinatorError> {
    let relevant: Vec<AssessmentRelation> = corrections
        .relations
        .iter()
        .filter(|relation| {
            evidence
                .resolve(&relation.prior)
                .is_some_and(|record| record.subject == source.subject)
        })
        .cloned()
        .collect();
    if relevant.is_empty() {
        return Ok(true);
    }
    match crate::learning::correction_view(
        &source.subject,
        evidence,
        &relevant,
        &corrections.delegations,
    )
    .map_err(refusal)?
    {
        Projection::Current { record, .. } => Ok(source.id == record),
        _ => Ok(false),
    }
}

fn validate_new_source(
    workspace: &politeia_core::institution::InstitutionWorkspace,
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
    source: &LearningSourceRequest,
) -> Result<(), CoordinatorError> {
    if source.trust_domain != workspace.trust_domain {
        return Err(CoordinatorError::Refused(
            "learning source trust domain differs from the installed workspace".to_string(),
        ));
    }
    if Digest::blake3(&source.content) != source.proposition {
        return Err(CoordinatorError::Refused(
            "learning source content digest differs from its proposition".to_string(),
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
            "learning source approval digest differs from the canonical durable approval wire"
                .to_string(),
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
    if fact.subject() != &source.subject {
        return Err(CoordinatorError::Refused(
            "learning source subject differs from the durable approved fact".to_string(),
        ));
    }
    if fact.proposition() != &source.proposition {
        return Err(CoordinatorError::Refused(
            "learning source proposition differs from the durable approved fact".to_string(),
        ));
    }
    if !source.evidence.contains(&source.id) {
        return Err(CoordinatorError::Refused(
            "learning source identity is absent from its declared evidence provenance".to_string(),
        ));
    }
    if source
        .evidence
        .iter()
        .any(|id| evidence.resolve(id).is_none())
    {
        return Err(CoordinatorError::Refused(
            "learning source names evidence absent from durable admission".to_string(),
        ));
    }
    if source
        .observations
        .iter()
        .any(|id| observations.resolve(id).is_none())
    {
        return Err(CoordinatorError::Refused(
            "learning source names an observation absent from durable admission".to_string(),
        ));
    }
    if source
        .captures
        .iter()
        .any(|id| captures.resolve(id).is_none())
    {
        return Err(CoordinatorError::Refused(
            "learning source names a capture absent from durable admission".to_string(),
        ));
    }
    Ok(())
}

fn durable_feedback(
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
    id: &CommissioningRecordId,
) -> Result<politeia_core::trust::Admitted<LearningIngress<FeedbackRequest>>, CoordinatorError> {
    let payload = durable
        .state
        .get(&format!("learning_feedback:{}", id.0))
        .ok_or_else(|| {
            CoordinatorError::Refused("correction feedback is not durably admitted".to_string())
        })?;
    let wire: SignedAdmissionWire<LearningIngress<FeedbackRequest>> =
        serde_json::from_slice(&payload.bytes).map_err(|_| {
            CoordinatorError::Refused(
                "durable feedback is not a signed feedback request".to_string(),
            )
        })?;
    let admitted = anchors
        .admit_expected(AdmissionKind::LearningFeedback, wire)
        .map_err(refusal)?;
    require_requester_signer(&admitted)?;
    if admitted.payload().id != *id {
        return Err(CoordinatorError::Refused(
            "durable feedback identity differs from its signed request".to_string(),
        ));
    }
    Ok(admitted)
}

fn require_requester_signer<T>(
    admitted: &politeia_core::trust::Admitted<LearningIngress<T>>,
) -> Result<(), CoordinatorError> {
    if admitted.signer() != &admitted.payload().requester {
        return Err(CoordinatorError::Refused(
            "learning requester differs from the verified envelope signer".to_string(),
        ));
    }
    Ok(())
}

fn delegation_leaf(
    chain: &[politeia_core::trust::Admitted<politeia_core::Delegation>],
) -> Result<&politeia_core::trust::Admitted<politeia_core::Delegation>, CoordinatorError> {
    chain
        .last()
        .ok_or_else(|| CoordinatorError::Refused("learning authority chain is empty".to_string()))
}

fn require_disclosure_requester_signer<T>(
    admitted: &politeia_core::trust::Admitted<LearningDisclosureIngress<T>>,
) -> Result<(), CoordinatorError> {
    if admitted.signer() != &admitted.payload().requester {
        return Err(CoordinatorError::Refused(
            "learning requester differs from the verified disclosure envelope signer".to_string(),
        ));
    }
    Ok(())
}

fn require_finite_disclosure_budget<T>(
    admitted: &politeia_core::trust::Admitted<LearningDisclosureIngress<T>>,
) -> Result<(), CoordinatorError> {
    if !admitted.payload().budget.is_finite() {
        return Err(CoordinatorError::Refused(
            "learning disclosure budget must be finite".to_string(),
        ));
    }
    Ok(())
}

fn durable_evidence(
    anchors: &politeia_core::trust::InstitutionTrustAnchors,
    durable: &WorkspaceSnapshot,
) -> Result<TrustedEvidenceRegistry, CoordinatorError> {
    let mut wires = Vec::new();
    for record in durable.evidence.values() {
        let envelope: SignedAdmissionWire<Value> = serde_json::from_slice(record.payload())
            .map_err(|_| {
                CoordinatorError::Refused(
                    "durable evidence journal entry is not a signed envelope".to_string(),
                )
            })?;
        if envelope.signer != *record.signer() || envelope.signature != record.signature() {
            return Err(CoordinatorError::Refused(
                "durable evidence record and wire binding differ".to_string(),
            ));
        }
        if envelope.kind != AdmissionKind::Evidence {
            continue;
        }
        let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(record.payload())
            .map_err(|_| {
            CoordinatorError::Refused(
                "durable evidence wire has the wrong payload type".to_string(),
            )
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use jiff::Timestamp;
    use politeia_core::{
        Delegation, Effect, ResourceBudget,
        evidence::{EvidenceRecord, IndependenceClass},
        institution::TrustDomainId,
    };
    use politeia_evidence::assessment::{RelationKind, SUPERSEDE_ACTION};

    fn at() -> Result<Timestamp, String> {
        "2026-09-09T00:00:00Z"
            .parse::<Timestamp>()
            .map_err(|error| error.to_string())
    }

    fn source(id: EvidenceId, subject: &Digest) -> Result<LearningSourceRequest, String> {
        let content = b"approved institutional content".to_vec();
        Ok(LearningSourceRequest {
            id: id.clone(),
            claim: politeia_core::ClaimId::new(),
            approval_digest: Digest::blake3(b"approval"),
            subject: subject.clone(),
            proposition: Digest::blake3(&content),
            content,
            evidence: BTreeSet::from([id]),
            observations: BTreeSet::new(),
            captures: BTreeSet::new(),
            adapter: AdapterId::new(),
            currency: KnowledgeCurrency::Canonical,
            data_classes: BTreeSet::from([DataClass::Internal]),
            audiences: BTreeSet::from(["operator".to_string()]),
            sinks: BTreeSet::from(["local".to_string()]),
            trust_domain: "institution:learning"
                .parse::<TrustDomainId>()
                .map_err(|error| error.to_string())?,
            relevance: 1,
        })
    }

    fn corrections(
        authority: PrincipalId,
        delegation_id: DelegationId,
        first: EvidenceId,
        second: EvidenceId,
    ) -> Result<DurableCorrections, String> {
        let at = at()?;
        let delegation = Delegation {
            id: delegation_id.clone(),
            issuer: authority.clone(),
            subject: authority.clone(),
            parent: None,
            actions: BTreeSet::from([SUPERSEDE_ACTION.to_string()]),
            resources: BTreeSet::new(),
            effects: BTreeSet::from([Effect::ReadInstitutionalContext]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["operator".to_string()]),
            expires_at: "2026-09-10T00:00:00Z"
                .parse::<Timestamp>()
                .map_err(|error| error.to_string())?,
            budget: ResourceBudget {
                wall_ms: None,
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        };
        let relation = AssessmentRelation {
            id: EvidenceId::new(),
            kind: RelationKind::Supersession,
            prior: first,
            successor: second,
            authority,
            authority_delegation: delegation_id.clone(),
            asserted_at: at,
        };
        Ok(DurableCorrections {
            relations: vec![relation],
            delegations: BTreeMap::from([(delegation_id, delegation)]),
        })
    }

    #[test]
    fn supersession_changes_context_selection_without_rewriting_source() -> Result<(), String> {
        let subject = Digest::blake3(b"billing");
        let authority = PrincipalId::new();
        let delegation = DelegationId::new();
        let prior = EvidenceId::new();
        let successor = EvidenceId::new();
        let registry = TrustedEvidenceRegistry::from_trusted_bootstrap([
            EvidenceRecord {
                id: prior.clone(),
                subject: subject.clone(),
                producer: authority.clone(),
                producer_delegation: delegation.clone(),
                method: "fixture".to_string(),
                payload_digest: Digest::blake3(b"prior"),
                observed_at: at()?,
                independence: IndependenceClass::HumanAuthority,
            },
            EvidenceRecord {
                id: successor.clone(),
                subject: subject.clone(),
                producer: authority.clone(),
                producer_delegation: delegation.clone(),
                method: "fixture".to_string(),
                payload_digest: Digest::blake3(b"successor"),
                observed_at: at()?,
                independence: IndependenceClass::HumanAuthority,
            },
        ])
        .map_err(|error| error.to_string())?;
        let prior_source = source(prior.clone(), &subject)?;
        let successor_source = source(successor.clone(), &subject)?;
        let corrections = corrections(authority, delegation, prior, successor)?;
        assert!(
            !source_survives_corrections(&prior_source, &registry, &corrections)
                .map_err(|error| error.to_string())?
        );
        assert!(
            source_survives_corrections(&successor_source, &registry, &corrections)
                .map_err(|error| error.to_string())?
        );
        assert_eq!(prior_source.content, b"approved institutional content");
        Ok(())
    }
}

#[cfg(test)]
mod correction_negative_test {
    use super::*;
    use std::collections::BTreeSet;

    use politeia_core::{
        Delegation, Effect, ResourceBudget,
        evidence::{EvidenceRecord, IndependenceClass},
    };
    use politeia_evidence::assessment::{RelationKind, SUPERSEDE_ACTION};

    #[test]
    fn conflicting_successors_withhold_context_source() -> Result<(), String> {
        let subject = Digest::blake3(b"billing");
        let authority = PrincipalId::new();
        let delegation_id = DelegationId::new();
        let prior = EvidenceId::new();
        let successor_a = EvidenceId::new();
        let successor_b = EvidenceId::new();
        let timestamp: jiff::Timestamp = "2026-09-09T00:00:00Z"
            .parse()
            .map_err(|error: jiff::Error| error.to_string())?;
        let registry = TrustedEvidenceRegistry::from_trusted_bootstrap(
            [prior.clone(), successor_a.clone(), successor_b.clone()]
                .into_iter()
                .map(|id| EvidenceRecord {
                    id,
                    subject: subject.clone(),
                    producer: authority.clone(),
                    producer_delegation: delegation_id.clone(),
                    method: "fixture".to_string(),
                    payload_digest: Digest::blake3(b"fixture"),
                    observed_at: timestamp,
                    independence: IndependenceClass::HumanAuthority,
                }),
        )
        .map_err(|error| error.to_string())?;
        let delegation = Delegation {
            id: delegation_id.clone(),
            issuer: authority.clone(),
            subject: authority.clone(),
            parent: None,
            actions: BTreeSet::from([SUPERSEDE_ACTION.to_string()]),
            resources: BTreeSet::new(),
            effects: BTreeSet::from([Effect::ReadInstitutionalContext]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["operator".to_string()]),
            expires_at: "2026-09-10T00:00:00Z"
                .parse::<jiff::Timestamp>()
                .map_err(|error| error.to_string())?,
            budget: ResourceBudget {
                wall_ms: None,
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        };
        let relations = [successor_a, successor_b]
            .into_iter()
            .map(|successor| AssessmentRelation {
                id: EvidenceId::new(),
                kind: RelationKind::Supersession,
                prior: prior.clone(),
                successor,
                authority: authority.clone(),
                authority_delegation: delegation_id.clone(),
                asserted_at: timestamp,
            })
            .collect();
        let corrections = DurableCorrections {
            relations,
            delegations: BTreeMap::from([(delegation_id.clone(), delegation)]),
        };
        let source = LearningSourceRequest {
            id: prior.clone(),
            claim: politeia_core::ClaimId::new(),
            approval_digest: Digest::blake3(b"approval"),
            subject,
            proposition: Digest::blake3(b"content"),
            content: b"content".to_vec(),
            evidence: BTreeSet::from([prior]),
            observations: BTreeSet::new(),
            captures: BTreeSet::new(),
            adapter: AdapterId::new(),
            currency: KnowledgeCurrency::Canonical,
            data_classes: BTreeSet::from([DataClass::Internal]),
            audiences: BTreeSet::from(["operator".to_string()]),
            sinks: BTreeSet::from(["local".to_string()]),
            trust_domain: "institution:learning"
                .parse::<politeia_core::institution::TrustDomainId>()
                .map_err(|error| error.to_string())?,
            relevance: 1,
        };
        assert!(
            !source_survives_corrections(&source, &registry, &corrections)
                .map_err(|error| error.to_string())?
        );
        Ok(())
    }
}
