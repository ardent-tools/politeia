//! Authenticated service handlers for the institutional learning loop.
//!
//! The pure projections in [`crate::learning`] never see transport documents.
//! This module admits the exact signed requester envelopes, recovers only
//! durable signed knowledge, and commits feedback/proposals without making a
//! caller-authored fact or relation authoritative.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use jiff::Timestamp;
use politeia_core::{
    AdapterId, BudgetReservationId, CommissioningRecordId, DataClass, DelegationId, Digest, Effect,
    EffectLeaseId, EvidenceId, InstitutionId, InstitutionWorkspaceId, ObservationId, PrincipalId,
    ResourceBudget, RuntimeGenerationId, SourceCaptureId,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    knowledge::{
        FactApprovalRequest, SourceCaptureRequest, TrustedCandidateClaimRegistry,
        TrustedObservationRegistry, TrustedSourceCaptureRegistry, approve_claim,
    },
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use politeia_evidence::assessment::{AssessmentRelation, Projection};
use politeia_policy::PolicyDecision;
use politeia_runtime::{
    AuthorizationLedger, AuthorizedEffect, Dispatcher, DispatcherConfig, EffectLease, EffectPort,
    OperationIntent, PolicyDecisionPoint,
};
use politeia_storage::{
    CanonicalPayload, OperationOutboxMessage, PostgresAuthorizationLedger, ScopedCommit,
    SignedRecord, StateMutation, WorkspaceSnapshot,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    CoordinatorError, OperationResult,
    learning::{
        ActiveCapabilities, CapabilityRequest, CompiledContext, ContextRequest, ContextSource,
        FeedbackRequest, KnowledgeCurrency, LearningSnapshot,
    },
    service::{PoliteiadService, refusal, signed_wire_record, storage_refusal},
    service_operation::{
        AdmittedOperationalSubmission, COMPILE_CONTEXT_OPERATION, DISCOVER_CAPABILITIES_OPERATION,
        InstalledOperationHandler, OperationSubmission,
    },
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

/// Immutable receipt retained only after a disclosed result's claimed budget
/// reservation has completed with its transactional outbox message.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningDisclosureReceipt {
    schema: String,
    id: Uuid,
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    /// Canonical JSON view of the exact installed-key-signed primary request.
    request: Value,
    request_digest: Digest,
    subject: Digest,
    population: Digest,
    input_digest: Digest,
    generation: RuntimeGenerationId,
    lease: EffectLeaseId,
    reservation: BudgetReservationId,
    decision: PolicyDecision,
    completed_at: Timestamp,
    outcome: OperationResult,
}

/// Public evidence that a context or discovery response has completed its
/// durable reservation and committed its receipt/outbox record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningDisclosureCompletion {
    /// Immutable receipt identity retained by PostgreSQL.
    pub receipt: Uuid,
    /// Digest of the exact canonical receipt bytes.
    pub receipt_digest: Digest,
    /// Claimed reservation transitioned to completed with this receipt.
    pub reservation: BudgetReservationId,
    /// Runtime generation bound by the consumed effect lease.
    pub generation: RuntimeGenerationId,
    /// Transactional outbox message identity.
    pub outbox: Uuid,
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
        /// Separately signed active-generation operation, routing, capability,
        /// and control material. It stays outside `request`, whose wire digest
        /// is bound by the operation input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_submission: Option<OperationSubmission>,
    },
    /// Discover descriptive active-generation capabilities.
    DiscoverCapabilities {
        /// Signed requester/delegation-bound request.
        request: SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
        /// Separately signed active-generation operation, routing, capability,
        /// and control material. It stays outside `request`, whose wire digest
        /// is bound by the operation input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_submission: Option<OperationSubmission>,
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
            LearningRequest::CompileContext {
                request,
                active_submission,
            } => Box::pin(self.compile_context(request, active_submission)).await,
            LearningRequest::DiscoverCapabilities {
                request,
                active_submission,
            } => Box::pin(self.discover_capabilities(request, active_submission)).await,
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
        active_submission: Option<OperationSubmission>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningContext, wire.clone())
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
        let bootstrap = self
            .storage()
            .load_bootstrap(self.scope())
            .await
            .map_err(|error| storage_refusal(&error))?;
        let output = self.hydrate_context(&durable, &result)?;
        let resources = disclosure_resources(
            &self.workspace().id,
            result.items.iter().map(|item| item.source.clone()),
        );
        let request_digest = durable_signed_wire_digest(&wire)?;
        let population = disclosure_population(&result)?;
        let input_digest = Digest::blake3(
            &politeia_core::canonical::to_canonical_bytes(&(
                request_digest.clone(),
                population.clone(),
            ))
            .map_err(|error| {
                CoordinatorError::Refused(format!("learning input cannot bind: {error}"))
            })?,
        );
        if bootstrap.digest() != admitted.payload().input.generation.digest() {
            return Box::pin(self
                .compile_active_context(
                    &durable,
                    &wire,
                    &authority,
                    &resources,
                    &output,
                    input_digest,
                    active_submission.ok_or_else(|| {
                        CoordinatorError::Refused(
                            "active disclosure requires signed operation, routing, capability, and control evidence"
                                .to_string(),
                        )
                    })?,
                ))
            .await;
        }
        if active_submission.is_some() {
            return Err(CoordinatorError::Refused(
                "bootstrap disclosure must not carry active operational admission material"
                    .to_string(),
            ));
        }
        let data_classes = result
            .items
            .iter()
            .flat_map(|item| {
                snapshot
                    .sources
                    .iter()
                    .find(|source| source.id == item.source)
                    .into_iter()
                    .flat_map(|source| source.data_classes.iter().cloned())
            })
            .collect();
        let operation = bootstrap_context_operation(data_classes)?;
        let policy = BootstrapDisclosurePolicy {
            workspace: self.workspace().clone(),
            bootstrap: bootstrap.digest().clone(),
            requester: admitted.payload().requester.clone(),
            authority: authority
                .iter()
                .map(|grant| grant.payload().clone())
                .collect(),
            operation: operation.clone(),
            resources: resources.clone(),
            budget: admitted.payload().budget.clone(),
            request: request_digest.clone(),
            population: population.clone(),
            replay_key: format!("learning:{}", admitted.payload().id.0),
        };
        let port = ContextDisclosurePort {
            adapter: AdapterId::new(),
            audience: admitted.payload().input.audience.clone(),
            resources: resources.clone(),
            output,
            subject: request_digest,
            population,
            runtime: admitted.payload().input.generation.clone(),
            input_digest: input_digest.clone(),
        };
        let dispatcher = Dispatcher::new(
            policy,
            port,
            politeia_storage::PostgresAuthorizationLedger::for_bootstrap(
                self.storage().clone(),
                self.scope().clone(),
                bootstrap.digest().clone(),
            )
            .with_workspace_revision(durable.revision),
            DispatcherConfig::new(
                self.workspace().policy_bundle.clone(),
                self.workspace().policy_digest.clone(),
                admitted.payload().input.generation.clone(),
                format!("bootstrap-learning:{}", bootstrap.digest().as_str()),
                jiff::SignedDuration::from_mins(5),
                authority.iter().map(|grant| grant.payload().clone()),
                [operation.clone()],
            )
            .map_err(refusal)?,
        );
        let intent = OperationIntent {
            principal: admitted.payload().requester.clone(),
            input_digest,
            delegation_chain: authority
                .iter()
                .map(|grant| grant.payload().clone())
                .collect(),
            operation,
            resources,
            budget: admitted.payload().budget.clone(),
            idempotency_key: Some(format!("learning:{}", admitted.payload().id.0)),
            execution: None,
        };
        let lease = dispatcher.authorize(&intent).await.map_err(refusal)?;
        let output = dispatcher.execute(&lease).await.map_err(refusal)?;
        self.complete_disclosure(&wire, &lease, output).await
    }

    async fn discover_capabilities(
        &self,
        wire: SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
        active_submission: Option<OperationSubmission>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::LearningDiscovery, wire.clone())
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
        let mut snapshot = self
            .learning_snapshot(&durable, &admitted.payload().input.generation)
            .await?;
        let bootstrap = self
            .storage()
            .load_bootstrap(self.scope())
            .await
            .map_err(|error| storage_refusal(&error))?;
        if bootstrap.digest() != admitted.payload().input.generation.digest() {
            let registry = self.active_operational_registry().await?;
            if registry.generation() != &admitted.payload().input.generation {
                return Err(CoordinatorError::Refused(
                    "active learning disclosure generation differs from the live operational registry"
                        .to_string(),
                ));
            }
            let inventory = registry.execution().capability_inventory();
            snapshot.capabilities = ActiveCapabilities {
                operations: inventory
                    .operations
                    .into_iter()
                    .map(|operation| operation.spec.id)
                    .collect(),
                resources: inventory
                    .resources
                    .into_iter()
                    .map(|resource| resource.id)
                    .collect(),
            };
        }
        let result = crate::learning::discover_capabilities(
            &snapshot,
            &admitted.payload().requester,
            delegation.payload(),
            &admitted.payload().input,
            self.now().await?,
        )
        .map_err(refusal)?;
        let resources = disclosure_resources(&self.workspace().id, std::iter::empty());
        let request_digest = durable_signed_wire_digest(&wire)?;
        let population = capability_population(&result)?;
        let input_digest = Digest::blake3(
            &politeia_core::canonical::to_canonical_bytes(&(
                request_digest.clone(),
                population.clone(),
            ))
            .map_err(|error| {
                CoordinatorError::Refused(format!("learning input cannot bind: {error}"))
            })?,
        );
        let output = OperationResult::Coordinated {
            result: json!(result),
            evidence_refs: Vec::new(),
        };
        if bootstrap.digest() != admitted.payload().input.generation.digest() {
            return Box::pin(self
                .discover_active_capabilities(
                    &durable,
                    &wire,
                    &authority,
                    &resources,
                    &output,
                    input_digest,
                    active_submission.ok_or_else(|| {
                        CoordinatorError::Refused(
                            "active disclosure requires signed operation, routing, capability, and control evidence"
                                .to_string(),
                        )
                    })?,
                ))
            .await;
        }
        if active_submission.is_some() {
            return Err(CoordinatorError::Refused(
                "bootstrap discovery must not carry active operational admission material"
                    .to_string(),
            ));
        }
        self.bootstrap_disclosure(
            bootstrap.digest(),
            &wire,
            &admitted,
            &authority,
            resources,
            output,
            request_digest,
            population,
            input_digest,
            bootstrap_discovery_operation()?,
            admitted.payload().input.generation.clone(),
            disclosure_audience(delegation_leaf(&authority)?.payload())?,
            durable.revision,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the active context binding keeps its independently authenticated axes explicit"
    )]
    async fn compile_active_context(
        &self,
        durable: &WorkspaceSnapshot,
        wire: &SignedAdmissionWire<LearningDisclosureIngress<ContextRequest>>,
        authority: &[Admitted<politeia_core::Delegation>],
        resources: &BTreeSet<String>,
        output: &OperationResult,
        input_digest: Digest,
        submission: OperationSubmission,
    ) -> Result<OperationResult, CoordinatorError> {
        Box::pin(self.active_disclosure(
            durable,
            wire,
            authority,
            resources,
            output,
            input_digest,
            submission,
            &wire.payload.input.generation,
            &wire.payload.input.audience,
            COMPILE_CONTEXT_OPERATION,
            crate::learning::COMPILE_CONTEXT_ACTION,
        ))
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the active capability binding keeps its independently authenticated axes explicit"
    )]
    async fn discover_active_capabilities(
        &self,
        durable: &WorkspaceSnapshot,
        wire: &SignedAdmissionWire<LearningDisclosureIngress<CapabilityRequest>>,
        authority: &[Admitted<politeia_core::Delegation>],
        resources: &BTreeSet<String>,
        output: &OperationResult,
        input_digest: Digest,
        submission: OperationSubmission,
    ) -> Result<OperationResult, CoordinatorError> {
        Box::pin(self.active_disclosure(
            durable,
            wire,
            authority,
            resources,
            output,
            input_digest,
            submission,
            &wire.payload.input.generation,
            &disclosure_audience(delegation_leaf(authority)?.payload())?,
            DISCOVER_CAPABILITIES_OPERATION,
            crate::learning::DISCOVER_CAPABILITIES_ACTION,
        ))
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each authenticated disclosure binding axis is explicit at the service boundary"
    )]
    async fn active_disclosure<T: Serialize>(
        &self,
        durable: &WorkspaceSnapshot,
        wire: &SignedAdmissionWire<LearningDisclosureIngress<T>>,
        authority: &[Admitted<politeia_core::Delegation>],
        resources: &BTreeSet<String>,
        output: &OperationResult,
        input_digest: Digest,
        submission: OperationSubmission,
        generation: &RuntimeGenerationId,
        audience: &str,
        operation_name: &str,
        action: &str,
    ) -> Result<OperationResult, CoordinatorError> {
        let signed_intent = self
            .anchors()
            .admit_expected(AdmissionKind::OperationIntent, submission.intent.clone())
            .map_err(refusal)?;
        if signed_intent.signer() != &wire.payload.requester {
            return Err(CoordinatorError::Refused(
                "active disclosure operation intent signer differs from the signed learning requester"
                    .to_string(),
            ));
        }
        verify_active_disclosure_intent(
            signed_intent.payload(),
            authority,
            resources,
            &wire.payload.budget,
            &input_digest,
            &wire.payload.id,
            operation_name,
            action,
        )?;

        let admitted = self
            .admit_operational_submission(durable, submission)
            .await?;
        if admitted.registry().generation() != generation {
            return Err(CoordinatorError::Refused(
                "active disclosure operation does not use the requested active generation"
                    .to_string(),
            ));
        }
        if admitted.registered().spec.name != operation_name
            || !active_handler_matches(&admitted, operation_name)
        {
            return Err(CoordinatorError::Refused(
                "active disclosure operation is not installed for this learning endpoint"
                    .to_string(),
            ));
        }
        verify_active_disclosure_intent(
            admitted.intent(),
            authority,
            resources,
            &wire.payload.budget,
            &input_digest,
            &wire.payload.id,
            operation_name,
            action,
        )?;

        let evaluation = politeia_policy::operational::OperationalEvaluationRequest {
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            intent_digest: admitted.intent().digest().map_err(|error| {
                CoordinatorError::Refused(format!("active disclosure intent cannot bind: {error}"))
            })?,
            principal: admitted.intent().principal.clone(),
            operation: admitted.intent().operation.clone(),
            resources: admitted.intent().resources.clone(),
            // The normalized subject and population do not vary with this
            // instant; admission itself evaluates with the ledger's DB clock.
            at: self.now().await?,
        };
        let normalized = evaluation
            .evaluation_subject(admitted.registry().policy())
            .map_err(|error| {
                CoordinatorError::Refused(format!(
                    "active disclosure policy subject cannot bind: {error}"
                ))
            })?;
        if admitted.decision().subject != normalized.subject
            || admitted.decision().population != normalized.population
        {
            return Err(CoordinatorError::Refused(
                "active policy decision differs from the normalized disclosure subject and population"
                    .to_string(),
            ));
        }
        let selected_resource = admitted
            .registry()
            .execution()
            .resource(&admitted.assignment().resource)
            .ok_or_else(|| {
                CoordinatorError::Refused(
                    "active disclosure routing selected an unknown execution resource".to_string(),
                )
            })?;
        let port = ContextDisclosurePort {
            adapter: selected_resource.adapter.clone(),
            audience: audience.to_string(),
            resources: resources.clone(),
            output: output.clone(),
            subject: normalized.subject,
            population: normalized.population,
            runtime: generation.clone(),
            input_digest,
        };
        let dispatcher = admitted.dispatcher(
            port,
            politeia_storage::PostgresAuthorizationLedger::new(
                self.storage().clone(),
                self.scope().clone(),
            )
            .with_workspace_revision(admitted.admission_revision()),
        )?;
        let lease = dispatcher
            .authorize(admitted.intent())
            .await
            .map_err(refusal)?;
        let output = dispatcher.execute(&lease).await.map_err(refusal)?;
        self.complete_disclosure(wire, &lease, output).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "bootstrap disclosure also binds each durable authorization axis explicitly"
    )]
    async fn bootstrap_disclosure<T: Serialize>(
        &self,
        bootstrap: &Digest,
        wire: &SignedAdmissionWire<LearningDisclosureIngress<T>>,
        admitted: &Admitted<LearningDisclosureIngress<T>>,
        authority: &[Admitted<politeia_core::Delegation>],
        resources: BTreeSet<String>,
        output: OperationResult,
        request: Digest,
        population: Digest,
        input_digest: Digest,
        operation: politeia_core::OperationSpec,
        runtime: RuntimeGenerationId,
        audience: String,
        revision: i64,
    ) -> Result<OperationResult, CoordinatorError> {
        let policy = BootstrapDisclosurePolicy {
            workspace: self.workspace().clone(),
            bootstrap: bootstrap.clone(),
            requester: admitted.payload().requester.clone(),
            authority: authority
                .iter()
                .map(|grant| grant.payload().clone())
                .collect(),
            operation: operation.clone(),
            resources: resources.clone(),
            budget: admitted.payload().budget.clone(),
            request: request.clone(),
            population: population.clone(),
            replay_key: format!("learning:{}", admitted.payload().id.0),
        };
        let port = ContextDisclosurePort {
            adapter: AdapterId::new(),
            audience,
            resources: resources.clone(),
            output,
            subject: request,
            population,
            runtime: runtime.clone(),
            input_digest: input_digest.clone(),
        };
        let dispatcher = Dispatcher::new(
            policy,
            port,
            politeia_storage::PostgresAuthorizationLedger::for_bootstrap(
                self.storage().clone(),
                self.scope().clone(),
                bootstrap.clone(),
            )
            .with_workspace_revision(revision),
            DispatcherConfig::new(
                self.workspace().policy_bundle.clone(),
                self.workspace().policy_digest.clone(),
                runtime,
                format!("bootstrap-learning:{}", bootstrap.as_str()),
                jiff::SignedDuration::from_mins(5),
                authority.iter().map(|grant| grant.payload().clone()),
                [operation.clone()],
            )
            .map_err(refusal)?,
        );
        let intent = OperationIntent {
            principal: admitted.payload().requester.clone(),
            input_digest,
            delegation_chain: authority
                .iter()
                .map(|grant| grant.payload().clone())
                .collect(),
            operation,
            resources,
            budget: admitted.payload().budget.clone(),
            idempotency_key: Some(format!("learning:{}", admitted.payload().id.0)),
            execution: None,
        };
        let lease = dispatcher.authorize(&intent).await.map_err(refusal)?;
        let output = dispatcher.execute(&lease).await.map_err(refusal)?;
        self.complete_disclosure(wire, &lease, output).await
    }

    async fn complete_disclosure<T: Serialize>(
        &self,
        request: &SignedAdmissionWire<LearningDisclosureIngress<T>>,
        lease: &EffectLease,
        outcome: OperationResult,
    ) -> Result<OperationResult, CoordinatorError> {
        let request_digest = durable_signed_wire_digest(request)?;
        let request = serde_json::to_value(request).map_err(|error| {
            CoordinatorError::Refused(format!(
                "learning disclosure receipt cannot encode request: {error}"
            ))
        })?;
        let completed_at =
            PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
                .observed_at()
                .await
                .map_err(refusal)?;
        let receipt_id = Uuid::now_v7();
        let receipt = LearningDisclosureReceipt {
            schema: "politeia.learning-disclosure-receipt.v1".to_string(),
            id: receipt_id,
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            request,
            request_digest,
            subject: lease.decision().subject.clone(),
            population: lease.decision().population.clone(),
            input_digest: lease.input_digest().clone(),
            generation: lease.runtime().clone(),
            lease: lease.id().clone(),
            reservation: lease.reservation_id().clone(),
            decision: lease.decision().clone(),
            completed_at,
            outcome,
        };
        let canonical_receipt = CanonicalPayload::from_serializable(&receipt)
            .map_err(|error| storage_refusal(&error))?;
        let outbox_id = Uuid::now_v7();
        let completion = LearningDisclosureCompletion {
            receipt: receipt_id,
            receipt_digest: canonical_receipt.digest().clone(),
            reservation: lease.reservation_id().clone(),
            generation: lease.runtime().clone(),
            outbox: outbox_id,
        };
        let response = disclosure_completion_response(receipt.outcome.clone(), &completion)?;
        self.storage()
            .record_completion_with_outbox(
                self.scope(),
                lease.reservation_id(),
                &canonical_receipt,
                &[OperationOutboxMessage {
                    id: outbox_id,
                    topic: "politeia.learning.disclosure.completed.v1".to_string(),
                    payload: canonical_receipt.clone(),
                }],
            )
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(response)
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

    #[expect(
        clippy::too_many_arguments,
        reason = "the commit retains separately authenticated provenance and live authority axes"
    )]
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
        let bootstrap = self
            .storage()
            .load_bootstrap(self.scope())
            .await
            .map_err(|error| storage_refusal(&error))?;
        if durable.active_generation.as_ref() != Some(generation.digest())
            && bootstrap.digest() != generation.digest()
        {
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

fn disclosure_audience(delegation: &politeia_core::Delegation) -> Result<String, CoordinatorError> {
    delegation.audience.iter().next().cloned().ok_or_else(|| {
        CoordinatorError::Refused(
            "learning disclosure delegation has no permitted audience".to_string(),
        )
    })
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

/// Derive every resource a disclosure may touch from admitted facts rather
/// than from caller-selected labels. These strings are carried unchanged by
/// the runtime intent, the policy wrapper, and the disclosure effect port.
fn disclosure_resources(
    workspace: &politeia_core::InstitutionWorkspaceId,
    sources: impl IntoIterator<Item = EvidenceId>,
) -> BTreeSet<String> {
    let mut resources = BTreeSet::from([crate::learning::context_workspace_resource(workspace)]);
    for source in sources {
        resources.insert(crate::learning::context_source_resource(workspace, &source));
    }
    resources
}

fn disclosure_population(context: &CompiledContext) -> Result<Digest, CoordinatorError> {
    let selected: Vec<_> = context
        .items
        .iter()
        .map(|item| (&item.source, &item.content.proposition))
        .collect();
    politeia_core::canonical::to_canonical_bytes(&selected)
        .map(|bytes| Digest::blake3(&bytes))
        .map_err(|error| {
            CoordinatorError::Refused(format!("context selection cannot bind: {error}"))
        })
}

fn capability_population(
    capabilities: &crate::learning::CapabilityDiscovery,
) -> Result<Digest, CoordinatorError> {
    politeia_core::canonical::to_canonical_bytes(&(
        &capabilities.operations,
        &capabilities.resources,
    ))
    .map(|bytes| Digest::blake3(&bytes))
    .map_err(|error| {
        CoordinatorError::Refused(format!("capability selection cannot bind: {error}"))
    })
}

fn active_handler_matches(admitted: &AdmittedOperationalSubmission, operation_name: &str) -> bool {
    matches!(
        (&admitted.registered().handler, operation_name),
        (
            InstalledOperationHandler::CompileInstitutionalContext,
            COMPILE_CONTEXT_OPERATION
        ) | (
            InstalledOperationHandler::DiscoverInstitutionalCapabilities,
            DISCOVER_CAPABILITIES_OPERATION,
        )
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the exact signed-request-to-operation mapping is security critical"
)]
fn verify_active_disclosure_intent(
    intent: &OperationIntent,
    authority: &[Admitted<politeia_core::Delegation>],
    resources: &BTreeSet<String>,
    budget: &ResourceBudget,
    input_digest: &Digest,
    request_id: &CommissioningRecordId,
    operation_name: &str,
    action: &str,
) -> Result<(), CoordinatorError> {
    let expected_chain: Vec<_> = authority
        .iter()
        .map(|grant| grant.payload().clone())
        .collect();
    if intent.delegation_chain != expected_chain {
        return Err(CoordinatorError::Refused(
            "active disclosure operation delegation chain differs from the live signed authority"
                .to_string(),
        ));
    }
    if intent.input_digest != *input_digest {
        return Err(CoordinatorError::Refused(
            "active disclosure operation input does not bind the signed request and selected population"
                .to_string(),
        ));
    }
    if &intent.resources != resources {
        return Err(CoordinatorError::Refused(
            "active disclosure operation resources differ from the approved context selection"
                .to_string(),
        ));
    }
    if &intent.budget != budget || !intent.budget.is_finite() {
        return Err(CoordinatorError::Refused(
            "active disclosure operation budget differs from the finite signed request".to_string(),
        ));
    }
    if intent.idempotency_key.as_deref() != Some(&format!("learning:{}", request_id.0)) {
        return Err(CoordinatorError::Refused(
            "active disclosure operation replay key differs from the signed request identity"
                .to_string(),
        ));
    }
    if intent.operation.name != operation_name
        || intent.operation.actions != BTreeSet::from([action.to_string()])
        || intent.operation.effects != BTreeSet::from([Effect::ReadInstitutionalContext])
        || intent.operation.retryable
        || !intent.operation.requires_idempotency
    {
        return Err(CoordinatorError::Refused(
            "active disclosure operation contract is not the installed non-retryable context-read operation"
                .to_string(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::enum_variant_names,
    reason = "each variant names the rejected lease axis"
)]
#[derive(Debug)]
enum LearningDisclosureRefusal {
    AuthorityMismatch,
    OperationMismatch,
    ResourceMismatch,
    BudgetMismatch,
}

impl fmt::Display for LearningDisclosureRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AuthorityMismatch => {
                "disclosure intent delegation chain differs from live authority"
            }
            Self::OperationMismatch => "disclosure intent operation differs from active registry",
            Self::ResourceMismatch => {
                "disclosure intent resources differ from signed approved disclosure"
            }
            Self::BudgetMismatch => "disclosure intent budget differs from signed finite budget",
        };
        formatter.write_str(message)
    }
}

impl Error for LearningDisclosureRefusal {}

fn bootstrap_context_operation(
    data_classes: BTreeSet<DataClass>,
) -> Result<politeia_core::OperationSpec, CoordinatorError> {
    let id = serde_json::from_value(serde_json::json!("00000000-0000-7000-8000-000000000001"))
        .map_err(|error| {
            CoordinatorError::Refused(format!("bootstrap operation identity invalid: {error}"))
        })?;
    Ok(politeia_core::OperationSpec {
        id,
        name: "bootstrap.compile_institutional_context".to_string(),
        actions: BTreeSet::from([crate::learning::COMPILE_CONTEXT_ACTION.to_string()]),
        effects: BTreeSet::from([Effect::ReadInstitutionalContext]),
        data_classes,
        evidence_obligations: vec!["learning.bootstrap.disclosure.v1".to_string()],
        execution_requirement: None,
        retryable: false,
        requires_idempotency: true,
    })
}

fn bootstrap_discovery_operation() -> Result<politeia_core::OperationSpec, CoordinatorError> {
    let id = serde_json::from_value(serde_json::json!("00000000-0000-7000-8000-000000000002"))
        .map_err(|error| {
            CoordinatorError::Refused(format!("bootstrap discovery identity invalid: {error}"))
        })?;
    Ok(politeia_core::OperationSpec {
        id,
        name: "bootstrap.discover_institutional_capabilities".to_string(),
        actions: BTreeSet::from([crate::learning::DISCOVER_CAPABILITIES_ACTION.to_string()]),
        effects: BTreeSet::from([Effect::ReadInstitutionalContext]),
        data_classes: BTreeSet::from([DataClass::Public]),
        evidence_obligations: vec!["learning.bootstrap.discovery.v1".to_string()],
        execution_requirement: None,
        retryable: false,
        requires_idempotency: true,
    })
}

struct BootstrapDisclosurePolicy {
    workspace: politeia_core::institution::InstitutionWorkspace,
    bootstrap: Digest,
    requester: PrincipalId,
    authority: Vec<politeia_core::Delegation>,
    operation: politeia_core::OperationSpec,
    resources: BTreeSet<String>,
    budget: ResourceBudget,
    request: Digest,
    population: Digest,
    replay_key: String,
}

impl PolicyDecisionPoint for BootstrapDisclosurePolicy {
    type Error = LearningDisclosureRefusal;

    async fn decide(
        &self,
        intent: &OperationIntent,
    ) -> Result<politeia_policy::PolicyDecision, Self::Error> {
        if intent.principal != self.requester || intent.delegation_chain != self.authority {
            return Err(LearningDisclosureRefusal::AuthorityMismatch);
        }
        if intent.operation != self.operation || intent.resources != self.resources {
            return Err(LearningDisclosureRefusal::ResourceMismatch);
        }
        if intent.budget != self.budget
            || !intent.budget.is_finite()
            || intent.idempotency_key.as_deref() != Some(&self.replay_key)
        {
            return Err(LearningDisclosureRefusal::BudgetMismatch);
        }
        Ok(politeia_policy::PolicyDecision {
            bundle: self.workspace.policy_bundle.clone(),
            policy_digest: self.workspace.policy_digest.clone(),
            intent_digest: intent
                .digest()
                .map_err(|_| LearningDisclosureRefusal::OperationMismatch)?,
            subject: self.request.clone(),
            population: self.population.clone(),
            principal: self.requester.clone(),
            allowed: true,
            binding_ids: vec!["politeia.bootstrap.learning-disclosure.v1".to_string()],
            control_runs: Vec::new(),
            activation_proofs: Vec::new(),
            waiver_ids: Vec::new(),
            reasons: vec![format!(
                "owner-pinned bootstrap disclosure {}",
                self.bootstrap.as_str()
            )],
        })
    }
}

#[derive(Debug)]
struct ContextPortError;
impl fmt::Display for ContextPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("context lease does not match disclosure")
    }
}
impl Error for ContextPortError {}
fn disclosure_completion_response(
    outcome: OperationResult,
    completion: &LearningDisclosureCompletion,
) -> Result<OperationResult, CoordinatorError> {
    let OperationResult::Coordinated {
        mut result,
        evidence_refs,
    } = outcome
    else {
        return Err(CoordinatorError::Refused(
            "learning disclosure port returned a non-coordinated result".to_string(),
        ));
    };
    let fields = result.as_object_mut().ok_or_else(|| {
        CoordinatorError::Refused(
            "learning disclosure port returned a non-object result".to_string(),
        )
    })?;
    fields.insert(
        "completion".to_string(),
        serde_json::to_value(completion).map_err(|error| {
            CoordinatorError::Refused(format!(
                "learning disclosure completion cannot encode response: {error}"
            ))
        })?,
    );
    Ok(OperationResult::Coordinated {
        result,
        evidence_refs,
    })
}

struct ContextDisclosurePort {
    adapter: AdapterId,
    audience: String,
    resources: BTreeSet<String>,
    output: OperationResult,
    subject: Digest,
    population: Digest,
    runtime: RuntimeGenerationId,
    input_digest: Digest,
}
impl EffectPort for ContextDisclosurePort {
    type Output = OperationResult;
    type Error = ContextPortError;
    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    fn audience(&self) -> &str {
        &self.audience
    }
    async fn execute<'a>(
        &'a self,
        effect: AuthorizedEffect<'a>,
    ) -> Result<Self::Output, Self::Error> {
        if effect.lease().resources() != &self.resources
            || effect.lease().decision().subject != self.subject
            || effect.lease().decision().population != self.population
            || effect.lease().runtime() != &self.runtime
            || effect.lease().input_digest() != &self.input_digest
        {
            return Err(ContextPortError);
        }
        Ok(self.output.clone())
    }
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

    #[test]
    fn disclosure_response_exposes_only_a_durable_completion_identity() -> Result<(), String> {
        let completion = LearningDisclosureCompletion {
            receipt: Uuid::now_v7(),
            receipt_digest: Digest::blake3(b"receipt"),
            reservation: BudgetReservationId::new(),
            generation: RuntimeGenerationId::derive(b"generation"),
            outbox: Uuid::now_v7(),
        };
        let result = disclosure_completion_response(
            OperationResult::Coordinated {
                result: json!({"context": [{"content": [1, 2, 3]}]}),
                evidence_refs: vec!["approved-source:one".to_string()],
            },
            &completion,
        )
        .map_err(|error| error.to_string())?;
        let OperationResult::Coordinated {
            result,
            evidence_refs,
        } = result
        else {
            panic!("disclosure completion changed the result kind");
        };
        assert_eq!(evidence_refs, vec!["approved-source:one"]);
        assert_eq!(result["completion"]["receipt"], json!(completion.receipt));
        assert_eq!(
            result["completion"]["reservation"],
            json!(completion.reservation)
        );
        assert_eq!(result["context"][0]["content"], json!([1, 2, 3]));
        Ok(())
    }

    #[test]
    fn disclosure_response_refuses_a_port_result_that_cannot_carry_completion() -> Result<(), String>
    {
        let completion = LearningDisclosureCompletion {
            receipt: Uuid::now_v7(),
            receipt_digest: Digest::blake3(b"receipt"),
            reservation: BudgetReservationId::new(),
            generation: RuntimeGenerationId::derive(b"generation"),
            outbox: Uuid::now_v7(),
        };
        let error = disclosure_completion_response(
            OperationResult::Coordinated {
                result: json!(["unstructured disclosure"]),
                evidence_refs: Vec::new(),
            },
            &completion,
        )
        .err()
        .ok_or_else(|| {
            "a response without a completion identity unexpectedly succeeded".to_string()
        })?;
        assert!(
            error
                .to_string()
                .contains("learning disclosure port returned a non-object result")
        );
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
