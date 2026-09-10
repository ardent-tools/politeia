//! The scoped application coordinator over installed trust and PostgreSQL.
//!
//! Transport passes opaque documents here. This module is the only place that
//! may admit them, select an internal adapter, or attach durable authority.

use std::{
    collections::{BTreeSet, HashSet},
    future::{Future, ready},
    path::PathBuf,
    pin::Pin,
};

use politeia_core::{
    Delegation, Digest,
    commissioning::CommissionerGrantRecord,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    institution::{InstitutionBoundary, InstitutionWorkspace},
    knowledge::{
        CandidateClaimRequest, FactApprovalRequest, ObservationRequest, SourceCaptureRequest,
        TrustedCandidateClaimRegistry, TrustedObservationRegistry, TrustedSourceCaptureRegistry,
        approve_claim,
    },
    reconnaissance::ReconnaissanceScope,
    trust::{
        AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire, WorkspaceBootstrapRequest,
    },
};
use politeia_policy::bootstrap::{
    BootstrapReconnaissance, BootstrapRefusal, bootstrap_capture_resources,
    bootstrap_reconnaissance_operation, evaluate_bootstrap_reconnaissance,
};
use politeia_runtime::{
    AuthorizationLedger, AuthorizedEffect, Dispatcher, DispatcherConfig, EffectPort,
    OperationIntent, PolicyDecisionPoint, RuntimeError,
};
use politeia_storage::{
    CanonicalPayload, EvidenceAdmission, PostgresAuthorizationLedger, PostgresStorage, Scope,
    ScopedCommit, SignedRecord, StateMutation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CommissioningCoordinator, CoordinatorError, OperationResult, SemanticOperation,
    config::InstallationLayout,
    service_operation::{
        CAPTURE_SOURCE_OPERATION, CapabilityEvidenceSubmission,
        DetectorCalibrationEvidenceSubmission, InstalledOperationHandler, OperationSubmission,
    },
};

/// One configured, single-workspace Politeia service.
///
/// Its constructor checks every static identity relation once; individual
/// operations still re-admit their signed input and verify current authority.
#[derive(Clone, Debug)]
pub struct PoliteiadService {
    layout: InstallationLayout,
    workspace: InstitutionWorkspace,
    anchors: InstitutionTrustAnchors,
    storage: PostgresStorage,
    scope: Scope,
    bootstrap: SignedAdmissionWire<WorkspaceBootstrapRequest>,
}

/// Signed source-capture material submitted through the semantic coordinator.
///
/// It remains inert until this service re-admits every wire, checks the
/// persisted delegation, and verifies an installed-root source capture.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCaptureSubmission {
    /// Descriptor-bounded capture signed by an installed principal.
    pub capture: SignedAdmissionWire<SourceCaptureRequest>,
    /// Evidence request for the source observation.
    pub evidence: SignedAdmissionWire<EvidenceRequest>,
    /// Observation request citing the exact capture and evidence.
    pub observation: SignedAdmissionWire<ObservationRequest>,
    /// Read-only authority required before the adapter reads.
    pub reconnaissance: ReconnaissanceScope,
    /// Active-generation routing and control material. It is mandatory once a
    /// runtime generation is active and ignored by the bootstrap-only path.
    #[serde(default)]
    pub operation: Option<OperationSubmission>,
}

/// One typed commissioning request accepted by the service.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommissioningRequest {
    /// Atomically revoke exact authority under the installed owner's signature.
    RevokeDelegation {
        /// Signed revocation retained as the decision evidence.
        request: SignedAdmissionWire<crate::service_revocation::DelegationRevocationRequest>,
    },
    /// Persist a signed delegation after installed-key admission.
    AdmitDelegation {
        /// Exact signed delegation wire, retained for restart re-admission.
        delegation: Box<SignedAdmissionWire<Delegation>>,
    },
    /// Handle a typed institutional learning request.
    Learning {
        /// Opaque transport JSON parsed only by the learning service boundary.
        request: Value,
    },
    /// Execute a typed signed generation lifecycle request.
    Generation {
        /// Opaque JSON decoded by the dedicated generation coordinator.
        request: Value,
    },
    /// Persist an interpreter-signed candidate and owner-approved fact.
    ApproveClaim {
        /// Complete candidate claim, signed by its interpreter.
        candidate: Box<SignedAdmissionWire<CandidateClaimRequest>>,
        /// Owner approval bound to that exact candidate digest.
        approval: SignedAdmissionWire<FactApprovalRequest>,
    },
    /// Admit one institution-owner commissioning approval as durable evidence.
    ///
    /// Its exact typed subject is checked only when a canonical commissioning
    /// record is derived, where the complete observation selection is known.
    CommissioningApproval {
        /// Owner-signed evidence for one typed commissioning subject.
        evidence: SignedAdmissionWire<EvidenceRequest>,
    },
    /// Reproduce and retain verifier-signed evidence for one exact execution
    /// capability record under its already admitted owner grant.
    CapabilityEvidence {
        /// Exact verification, grant, signed evidence, and public probe result.
        submission: Box<CapabilityEvidenceSubmission>,
    },
    /// Reproduce and retain signed activation evidence for one exact public
    /// operational detector.
    DetectorCalibrationEvidence {
        /// Policy bytes, actual calibration report, live grant, and signed evidence.
        submission: Box<DetectorCalibrationEvidenceSubmission>,
    },
}

impl PoliteiadService {
    /// Connect to PostgreSQL for an already-installed host configuration.
    ///
    /// This does not initialize a host, run migrations, or bootstrap a
    /// workspace. Those are separate explicit host-trust actions.
    pub async fn connect(
        layout: InstallationLayout,
        workspace: InstitutionWorkspace,
        anchors: InstitutionTrustAnchors,
        bootstrap: SignedAdmissionWire<WorkspaceBootstrapRequest>,
        database_url: &str,
    ) -> Result<Self, CoordinatorError> {
        if layout.institution != workspace.institution
            || layout.workspace != workspace.id
            || anchors.institution() != &workspace.institution
            || anchors.workspace() != &workspace.id
        {
            return Err(CoordinatorError::Refused(
                "installed layout, workspace, and trust anchors must name the same scope"
                    .to_string(),
            ));
        }
        let admitted_bootstrap = anchors
            .admit_workspace_bootstrap(bootstrap.clone())
            .map_err(refusal)?;
        if admitted_bootstrap.payload().workspace != workspace {
            return Err(CoordinatorError::Refused(
                "owner-signed bootstrap differs from installed workspace configuration".to_string(),
            ));
        }
        let scope = Scope::new(
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.trust_domain.clone(),
        );
        let storage = PostgresStorage::connect(database_url)
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(Self {
            layout,
            workspace,
            anchors,
            storage,
            scope,
            bootstrap,
        })
    }

    /// Apply PostgreSQL migrations as part of an explicit host setup action.
    pub async fn migrate(&self) -> Result<(), CoordinatorError> {
        self.storage
            .migrate()
            .await
            .map_err(|error| storage_refusal(&error))
    }

    /// Create or verify the owner-signed workspace skeleton in PostgreSQL.
    ///
    /// The skeleton only establishes durable host scope. It is not an approved
    /// model revision and does not make later knowledge or policy true.
    pub async fn initialize_storage(&self) -> Result<(), CoordinatorError> {
        self.migrate().await?;
        let admitted = self
            .anchors
            .admit_workspace_bootstrap(self.bootstrap.clone())
            .map_err(refusal)?;
        let record = signed_wire_record(&self.bootstrap)?;
        match self.storage.load_workspace(&self.scope).await {
            Ok(existing) => {
                let genesis = self
                    .storage
                    .load_bootstrap(&self.scope)
                    .await
                    .map_err(|error| storage_refusal(&error))?;
                if existing.owner != self.workspace.owner
                    || existing.owner_delegation != self.workspace.owner_delegation
                    || genesis.digest() != record.digest()
                {
                    return Err(CoordinatorError::Refused(
                        "existing durable workspace differs from installed bootstrap".to_string(),
                    ));
                }
                Ok(())
            }
            Err(politeia_storage::StorageError::NotFound) => self
                .storage
                .bootstrap_workspace(&politeia_storage::WorkspaceBootstrap {
                    scope: self.scope.clone(),
                    owner: admitted.payload().workspace.owner.clone(),
                    owner_delegation: admitted.payload().workspace.owner_delegation.clone(),
                    model: record,
                })
                .await
                .map_err(|error| storage_refusal(&error)),
            Err(error) => Err(storage_refusal(&error)),
        }
    }

    /// Return the installed non-secret filesystem layout.
    pub fn layout(&self) -> &InstallationLayout {
        &self.layout
    }

    /// Return the exact durable authority scope used for every storage call.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Return the host-installed key set used for every signed admission.
    pub fn anchors(&self) -> &InstitutionTrustAnchors {
        &self.anchors
    }

    /// Return the installed workspace configuration for adjacent lifecycle coordination.
    pub(crate) fn workspace(&self) -> &InstitutionWorkspace {
        &self.workspace
    }

    /// Return the PostgreSQL authority for adjacent lifecycle coordination.
    pub(crate) fn storage(&self) -> &PostgresStorage {
        &self.storage
    }

    /// Recover one coherent inert durable snapshot for adjacent lifecycle coordination.
    pub(crate) async fn durable_snapshot(
        &self,
    ) -> Result<politeia_storage::WorkspaceSnapshot, CoordinatorError> {
        self.storage
            .load_workspace(&self.scope)
            .await
            .map_err(|error| storage_refusal(&error))
    }

    async fn handle(
        &self,
        operation: SemanticOperation,
    ) -> Result<OperationResult, CoordinatorError> {
        match operation {
            SemanticOperation::Status => self.status().await,
            SemanticOperation::SnapshotSource { request } => {
                Box::pin(self.capture_source(request)).await
            }
            SemanticOperation::Initialize { .. } => Err(CoordinatorError::Refused(
                "initialization is a local host trust-anchor action, not a running-daemon request"
                    .to_string(),
            )),
            SemanticOperation::Commissioning { request } => self.commission(request).await,
            SemanticOperation::Operate { request } => self.handle_operation(request).await,
        }
    }

    async fn status(&self) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let active_generation = durable
            .active_generation
            .as_ref()
            .map(|digest| digest.as_str().to_string());
        Ok(OperationResult::Coordinated {
            result: json!({
                "institution": self.workspace.institution,
                "workspace": self.workspace.id,
                "trust_domain": self.workspace.trust_domain,
                "active_generation": active_generation,
                "revision": durable.revision,
            }),
            evidence_refs: Vec::new(),
        })
    }

    async fn capture_source(&self, value: Value) -> Result<OperationResult, CoordinatorError> {
        let submission: SourceCaptureSubmission =
            serde_json::from_value(value).map_err(|error| {
                CoordinatorError::Refused(format!(
                    "source capture input is not typed JSON: {error}"
                ))
            })?;
        let captures =
            TrustedSourceCaptureRegistry::admit_signed(&self.anchors, [submission.capture.clone()])
                .map_err(refusal)?;
        let capture = captures
            .resolve(&submission.capture.payload.id)
            .ok_or_else(|| {
                CoordinatorError::Refused("admitted capture is unavailable".to_string())
            })?;
        let request = capture.request();

        let durable = self
            .storage
            .load_workspace(&self.scope)
            .await
            .map_err(|error| storage_refusal(&error))?;
        if durable.owner != self.workspace.owner
            || durable.owner_delegation != self.workspace.owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "durable workspace owner differs from installed workspace skeleton".to_string(),
            ));
        }
        let persisted = durable
            .delegations
            .get(&request.reconnaissance_delegation)
            .ok_or_else(|| {
                CoordinatorError::Refused("capture delegation is not durably admitted".to_string())
            })?;
        if persisted.revoked {
            return Err(CoordinatorError::Refused(
                "capture delegation is revoked before source access".to_string(),
            ));
        }
        let delegation = self
            .anchors
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        if delegation.payload().id != request.reconnaissance_delegation
            || delegation.payload().subject != *capture.signer()
        {
            return Err(CoordinatorError::Refused(
                "capture signer does not hold its durable reconnaissance delegation".to_string(),
            ));
        }
        if request.reconnaissance != submission.reconnaissance {
            return Err(CoordinatorError::Refused(
                "signed capture reconnaissance scope differs from submitted scope".to_string(),
            ));
        }
        let now = PostgresAuthorizationLedger::new(self.storage.clone(), self.scope.clone())
            .observed_at()
            .await
            .map_err(|error| runtime_refusal(&error))?;
        if request.observed_at < persisted.admitted_at || request.observed_at > now {
            return Err(CoordinatorError::Refused(
                "capture observation is outside its durable authority interval".to_owned(),
            ));
        }
        submission
            .reconnaissance
            .admit_authority(delegation.payload(), now)
            .map_err(refusal)?;
        if !submission.reconnaissance.sources.contains(&request.source)
            || !submission
                .reconnaissance
                .adapters
                .contains(&request.adapter)
        {
            return Err(CoordinatorError::Refused(
                "capture source or adapter is outside the reconnaissance descriptor".to_string(),
            ));
        }

        let evidence =
            TrustedEvidenceRegistry::admit_signed(&self.anchors, [submission.evidence.clone()])
                .map_err(refusal)?;
        let observations = TrustedObservationRegistry::admit_signed(
            &self.workspace,
            &self.anchors,
            &evidence,
            &captures,
            [submission.observation.clone()],
        )
        .map_err(refusal)?;
        let observation = observations
            .resolve(&submission.observation.payload.id)
            .ok_or_else(|| {
                CoordinatorError::Refused("admitted observation is unavailable".to_string())
            })?;
        let boundary = InstitutionBoundary::new(
            self.workspace.institution.clone(),
            self.workspace.id.clone(),
            (),
        );
        submission
            .reconnaissance
            .admit(&boundary, delegation.payload(), observation, now)
            .map_err(refusal)?;

        let (lease, snapshot, authority_chain) = if durable.active_generation.is_some() {
            let operation = submission.operation.clone().ok_or_else(|| {
                CoordinatorError::Refused(
                    "active-generation source capture requires signed operational admission"
                        .to_string(),
                )
            })?;
            let input_digest = capture_operation_input_digest(&submission)?;
            let admitted = self
                .admit_operational_submission(&durable, operation)
                .await?;
            if admitted.registered().spec.name != CAPTURE_SOURCE_OPERATION
                || !matches!(
                    admitted.registered().handler,
                    InstalledOperationHandler::CaptureAuthorizedSource
                )
                || admitted.intent().principal != *capture.signer()
                || admitted.intent().input_digest != input_digest
                || admitted
                    .intent()
                    .delegation_chain
                    .last()
                    .is_none_or(|leaf| leaf.id != delegation.payload().id)
            {
                return Err(CoordinatorError::Refused(
                    "active operation does not bind the signed capture and its registered handler"
                        .to_string(),
                ));
            }
            if admitted.assignment().adapter != request.adapter {
                return Err(CoordinatorError::Refused(
                    "active routing assignment selects a different source adapter".to_string(),
                ));
            }
            let resources = bootstrap_capture_resources(request);
            if !capture_resources_match(&resources, &admitted.intent().resources) {
                return Err(CoordinatorError::Refused(
                    "active operation resources differ from the signed capture descriptor"
                        .to_string(),
                ));
            }
            let authority_chain = self.admit_durable_delegation_chain(
                &durable,
                &admitted.intent().delegation_chain,
                capture.signer(),
            )?;
            let port = InstalledCapturePort {
                root: self.layout.workspace_dir.clone(),
                request: request.clone(),
                resources,
                input_digest,
                audience: format!("institution:{}", self.workspace.institution.0),
            };
            let dispatcher = admitted.dispatcher(
                port,
                PostgresAuthorizationLedger::new(self.storage.clone(), self.scope.clone()),
            )?;
            let lease = dispatcher
                .authorize(admitted.intent())
                .await
                .map_err(|error| runtime_refusal(&error))?;
            let snapshot = dispatcher
                .execute(&lease)
                .await
                .map_err(|error| runtime_refusal(&error))?;
            (lease, snapshot, authority_chain)
        } else {
            if submission.operation.is_some() {
                return Err(CoordinatorError::Refused(
                    "bootstrap source capture does not accept active operational admission"
                        .to_string(),
                ));
            }
            let bootstrap = self
                .storage
                .load_bootstrap(&self.scope)
                .await
                .map_err(|error| storage_refusal(&error))?;
            let resources = bootstrap_capture_resources(request);
            let operation = bootstrap_reconnaissance_operation(
                politeia_core::OperationId::new(),
                delegation.payload().data_classes.clone(),
            );
            let policy = BootstrapCapturePolicy {
                workspace: self.workspace.clone(),
                captures: captures.clone(),
                capture: request.id.clone(),
                delegation: delegation.clone(),
                scope: submission.reconnaissance.clone(),
                bootstrap: bootstrap.digest().clone(),
                now,
            };
            let port = InstalledCapturePort {
                root: self.layout.workspace_dir.clone(),
                request: request.clone(),
                resources: resources.clone(),
                input_digest: capture_operation_input_digest(&submission)?,
                audience: format!("institution:{}", self.workspace.institution.0),
            };
            let dispatcher = Dispatcher::new(
                policy,
                port,
                PostgresAuthorizationLedger::for_bootstrap(
                    self.storage.clone(),
                    self.scope.clone(),
                    bootstrap.digest().clone(),
                )
                .with_workspace_revision(durable.revision),
                DispatcherConfig::new(
                    self.workspace.policy_bundle.clone(),
                    self.workspace.policy_digest.clone(),
                    politeia_core::RuntimeGenerationId::from_digest(bootstrap.digest().clone()),
                    format!("bootstrap:{}", bootstrap.digest().as_str()),
                    jiff::SignedDuration::from_mins(5),
                    [delegation.payload().clone()],
                    [operation.clone()],
                )
                .map_err(|error| runtime_refusal(&error))?,
            );
            let intent = OperationIntent {
                principal: capture.signer().clone(),
                input_digest: capture_operation_input_digest(&submission)?,
                delegation_chain: vec![delegation.payload().clone()],
                operation,
                resources,
                budget: delegation.payload().budget.clone(),
                idempotency_key: None,
                execution: None,
            };
            let lease = dispatcher
                .authorize(&intent)
                .await
                .map_err(|error| runtime_refusal(&error))?;
            let snapshot = dispatcher
                .execute(&lease)
                .await
                .map_err(|error| runtime_refusal(&error))?;
            (
                lease,
                snapshot,
                self.admit_durable_delegation_chain(
                    &durable,
                    std::slice::from_ref(delegation.payload()),
                    capture.signer(),
                )?,
            )
        };
        if snapshot.manifest_digest != request.content_manifest_digest {
            return Err(CoordinatorError::Refused(
                "installed source bytes do not match the signed capture content manifest"
                    .to_string(),
            ));
        }

        let capture_record = signed_wire_record(&submission.capture)?;
        let evidence_record = signed_wire_record(&submission.evidence)?;
        let observation_record = signed_wire_record(&submission.observation)?;
        let receipt = self
            .storage
            .commit_authorized(
                &ScopedCommit {
                    scope: self.scope.clone(),
                    expected_revision: durable.revision,
                    model: durable.model,
                    model_kind: "source_capture".to_string(),
                    transition: capture_record.clone(),
                    state: vec![
                        StateMutation {
                            key: format!("source_capture:{}", request.id.0),
                            value: capture_record,
                        },
                        StateMutation {
                            key: format!("observation:{}", observation.id.0),
                            value: observation_record,
                        },
                    ],
                    evidence: vec![EvidenceAdmission {
                        id: submission.evidence.payload.id.clone(),
                        record: evidence_record,
                    }],
                    outbox: Vec::new(),
                },
                &authority_chain,
            )
            .await
            .map_err(|error| storage_refusal(&error))?;
        self.storage
            .record_completion_with_outbox(
                &self.scope,
                lease.reservation_id(),
                &CanonicalPayload::from_serializable(&json!({
                    "kind": "source_capture_completion.v1",
                    "capture": request.id,
                    "observation": observation.id,
                    "evidence": submission.evidence.payload.id,
                    "snapshot_manifest": snapshot.manifest_digest,
                    "state_revision": receipt.revision,
                    "transition": receipt.transition_digest,
                }))
                .map_err(|error| storage_refusal(&error))?,
                &[],
            )
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "capture": request.id,
                "observation": observation.id,
                "snapshot_manifest": snapshot.manifest_digest,
                "revision": receipt.revision,
                "transition": receipt.transition_digest,
            }),
            evidence_refs: vec![submission.evidence.payload.id.0.to_string()],
        })
    }

    /// Rebuild signed provenance and accept one candidate only through an owner approval.
    async fn approve_candidate(
        &self,
        candidate: SignedAdmissionWire<CandidateClaimRequest>,
        approval: SignedAdmissionWire<FactApprovalRequest>,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let evidence = TrustedEvidenceRegistry::admit_signed(
            &self.anchors,
            durable
                .evidence
                .values()
                .map(evidence_wire)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(refusal)?;
        let captures = TrustedSourceCaptureRegistry::admit_signed(
            &self.anchors,
            durable
                .state
                .iter()
                .filter(|(key, _)| key.starts_with("source_capture:"))
                .map(|(_, value)| state_wire(value))
                .collect::<Result<Vec<SignedAdmissionWire<SourceCaptureRequest>>, _>>()?,
        )
        .map_err(refusal)?;
        let observations = TrustedObservationRegistry::admit_signed(
            &self.workspace,
            &self.anchors,
            &evidence,
            &captures,
            durable
                .state
                .iter()
                .filter(|(key, _)| key.starts_with("observation:"))
                .map(|(_, value)| state_wire(value))
                .collect::<Result<Vec<SignedAdmissionWire<ObservationRequest>>, _>>()?,
        )
        .map_err(refusal)?;
        let candidates = TrustedCandidateClaimRegistry::admit_signed(
            &self.workspace,
            &self.anchors,
            &observations,
            [candidate.clone()],
        )
        .map_err(refusal)?;
        let fact = approve_claim(
            &self.workspace,
            &observations,
            &self.anchors,
            &candidates,
            approval.clone(),
        )
        .map_err(refusal)?;
        let candidate_key = format!("candidate_claim:{}", fact.claim().0);
        let approval_key = format!("fact_approval:{}", fact.claim().0);
        if durable.state.contains_key(&candidate_key) || durable.state.contains_key(&approval_key) {
            return Err(CoordinatorError::Refused(
                "candidate or fact approval already has a durable projection".to_string(),
            ));
        }
        let candidate_record = signed_wire_record(&candidate)?;
        let approval_record = signed_wire_record(&approval)?;
        let receipt = self
            .storage
            .commit(&ScopedCommit {
                scope: self.scope.clone(),
                expected_revision: durable.revision,
                model: durable.model,
                model_kind: "fact_approval".to_string(),
                transition: approval_record.clone(),
                state: vec![
                    StateMutation {
                        key: candidate_key,
                        value: candidate_record,
                    },
                    StateMutation {
                        key: approval_key,
                        value: approval_record,
                    },
                ],
                evidence: Vec::new(),
                outbox: Vec::new(),
            })
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "claim": fact.claim(),
                "subject": fact.subject(),
                "proposition": fact.proposition(),
                "revision": receipt.revision,
                "transition": receipt.transition_digest,
                "approved": true,
            }),
            evidence_refs: Vec::new(),
        })
    }

    /// Admit owner-scoped commissioning approval evidence without inventing a
    /// separate approval protocol. The canonical commissioning record later
    /// resolves this evidence against all four required typed subjects.
    async fn admit_commissioning_approval(
        &self,
        approval: SignedAdmissionWire<EvidenceRequest>,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let evidence = TrustedEvidenceRegistry::admit_signed(&self.anchors, [approval.clone()])
            .map_err(refusal)?;
        let admitted = evidence.resolve(&approval.payload.id).ok_or_else(|| {
            CoordinatorError::Refused("admitted commissioning approval is unavailable".to_string())
        })?;
        if admitted.producer != self.workspace.owner
            || admitted.producer_delegation != self.workspace.owner_delegation
            || !matches!(
                admitted.independence,
                politeia_core::evidence::IndependenceClass::HumanAuthority
            )
            || admitted.method != "institution-owner commissioning approval.v1"
        {
            return Err(CoordinatorError::Refused(
                "commissioning approval is not owner-scoped human authority evidence".to_string(),
            ));
        }
        if durable.evidence.contains_key(&admitted.id) {
            return Err(CoordinatorError::Refused(
                "commissioning approval evidence is already durably admitted".to_string(),
            ));
        }
        let record = signed_wire_record(&approval)?;
        let receipt = self
            .storage
            .commit(&ScopedCommit {
                scope: self.scope.clone(),
                expected_revision: durable.revision,
                model: durable.model,
                model_kind: "commissioning_approval".to_string(),
                transition: record.clone(),
                state: Vec::new(),
                evidence: vec![EvidenceAdmission {
                    id: admitted.id.clone(),
                    record,
                }],
                outbox: Vec::new(),
            })
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "evidence": admitted.id,
                "subject": admitted.subject,
                "revision": receipt.revision,
                "transition": receipt.transition_digest,
                "admitted": true,
            }),
            evidence_refs: vec![approval.payload.id.0.to_string()],
        })
    }

    /// Re-admit one durable, unrevoked delegation held by the exact requester.
    ///
    /// This is the sole service-side recovery path for delegation authority:
    /// it revalidates the signed envelope, durable revocation state, and
    /// complete attenuation chain to the installed owner before exposing the
    /// typed grant to another coordinator module.
    #[allow(
        dead_code,
        reason = "the sibling learning coordinator consumes this boundary"
    )]
    pub(crate) async fn admit_live_delegation(
        &self,
        delegation_id: &politeia_core::DelegationId,
        requester: &politeia_core::PrincipalId,
    ) -> Result<politeia_core::trust::Admitted<Delegation>, CoordinatorError> {
        self.admit_live_delegation_chain(delegation_id, requester)
            .await?
            .pop()
            .ok_or_else(|| {
                CoordinatorError::Refused("delegation authority chain is empty".to_string())
            })
    }

    /// Recover the exact root-to-leaf authority chain for a requester-bound
    /// delegation so durable commits can recheck every ancestor atomically.
    pub(crate) async fn admit_live_delegation_chain(
        &self,
        delegation_id: &politeia_core::DelegationId,
        requester: &politeia_core::PrincipalId,
    ) -> Result<Vec<politeia_core::trust::Admitted<Delegation>>, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let persisted = durable.delegations.get(delegation_id).ok_or_else(|| {
            CoordinatorError::Refused("delegation is not durably admitted".to_string())
        })?;
        if persisted.revoked {
            return Err(CoordinatorError::Refused(
                "delegation is revoked".to_string(),
            ));
        }
        let admitted = self
            .anchors
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        if admitted.payload().id != *delegation_id || admitted.payload().subject != *requester {
            return Err(CoordinatorError::Refused(
                "requester does not hold the requested delegation".to_string(),
            ));
        }
        self.validate_delegation_authority(&durable, &admitted)?;
        let mut leaf_to_root = vec![admitted.payload().clone()];
        while let Some(parent) = leaf_to_root
            .last()
            .and_then(|current| current.parent.clone())
        {
            let persisted = durable.delegations.get(&parent).ok_or_else(|| {
                CoordinatorError::Refused("delegation parent is not durably admitted".to_string())
            })?;
            if persisted.revoked {
                return Err(CoordinatorError::Refused(
                    "delegation parent is revoked".to_string(),
                ));
            }
            leaf_to_root.push(persisted.wire.payload.clone());
        }
        leaf_to_root.reverse();
        self.admit_durable_delegation_chain(&durable, &leaf_to_root, requester)
    }

    /// Re-admit one exact root-to-leaf delegation list from an already loaded
    /// durable snapshot. Runtime callers use this to bind every untrusted
    /// operation-chain member to its stored signed wire without a second read.
    pub(crate) fn admit_durable_delegation_chain(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        expected: &[Delegation],
        requester: &politeia_core::PrincipalId,
    ) -> Result<Vec<politeia_core::trust::Admitted<Delegation>>, CoordinatorError> {
        if expected.is_empty()
            || expected
                .last()
                .is_none_or(|leaf| leaf.subject != *requester)
        {
            return Err(CoordinatorError::Refused(
                "delegation chain does not end at the requester".to_string(),
            ));
        }
        let admitted = expected
            .iter()
            .map(|delegation| {
                let persisted = durable.delegations.get(&delegation.id).ok_or_else(|| {
                    CoordinatorError::Refused(
                        "delegation chain member is not durably admitted".to_string(),
                    )
                })?;
                if persisted.revoked {
                    return Err(CoordinatorError::Refused(
                        "delegation chain member is revoked".to_string(),
                    ));
                }
                let admitted = self
                    .anchors
                    .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
                    .map_err(refusal)?;
                if admitted.payload() != delegation {
                    return Err(CoordinatorError::Refused(
                        "delegation chain member differs from durable admission".to_string(),
                    ));
                }
                Ok(admitted)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (parent, child) in admitted.iter().zip(admitted.iter().skip(1)) {
            if child.payload().parent.as_ref() != Some(&parent.payload().id)
                || child.payload().issuer != parent.payload().subject
                || !child.payload().is_attenuation_of(parent.payload())
            {
                return Err(CoordinatorError::Refused(
                    "delegation chain is not ordered root-to-leaf attenuation".to_string(),
                ));
            }
        }
        self.validate_delegation_authority(
            durable,
            admitted.last().ok_or_else(|| {
                CoordinatorError::Refused("delegation chain is empty".to_string())
            })?,
        )?;
        Ok(admitted)
    }

    /// Re-admit one durable root-to-leaf chain as it stood at a retained
    /// historical instant. Later revocation remains preserved in storage but
    /// cannot erase authority that was valid when a signed capture occurred.
    pub(crate) fn admit_historical_delegation_chain(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        delegation_id: &politeia_core::DelegationId,
        requester: &politeia_core::PrincipalId,
        at: jiff::Timestamp,
    ) -> Result<Vec<politeia_core::trust::Admitted<Delegation>>, CoordinatorError> {
        if durable.owner != self.workspace.owner
            || durable.owner_delegation != self.workspace.owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "durable workspace owner differs from installed workspace skeleton".to_string(),
            ));
        }
        let mut leaf_to_root = Vec::new();
        let mut current = delegation_id.clone();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return Err(CoordinatorError::Refused(
                    "historical delegation chain contains a cycle".to_string(),
                ));
            }
            let persisted = durable.delegations.get(&current).ok_or_else(|| {
                CoordinatorError::Refused(
                    "historical delegation is not durably admitted".to_string(),
                )
            })?;
            if persisted.admitted_at > at
                || persisted.revoked_at.is_some_and(|revoked| revoked <= at)
                || persisted.wire.payload.expires_at <= at
            {
                return Err(CoordinatorError::Refused(
                    "historical delegation was not live at the retained capture instant"
                        .to_string(),
                ));
            }
            let admitted = self
                .anchors
                .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
                .map_err(refusal)?;
            if admitted.signer() != &admitted.payload().issuer {
                return Err(CoordinatorError::Refused(
                    "historical delegation envelope signer is not its semantic issuer".to_string(),
                ));
            }
            if let Some(parent) = admitted.payload().parent.clone() {
                current = parent;
                leaf_to_root.push(admitted);
            } else {
                if admitted.payload().issuer != self.workspace.owner {
                    return Err(CoordinatorError::Refused(
                        "historical delegation chain is not rooted in the installed owner"
                            .to_string(),
                    ));
                }
                leaf_to_root.push(admitted);
                break;
            }
        }
        leaf_to_root.reverse();
        if leaf_to_root
            .last()
            .is_none_or(|leaf| leaf.payload().subject != *requester)
        {
            return Err(CoordinatorError::Refused(
                "historical delegation chain does not end at the capture signer".to_string(),
            ));
        }
        for (parent, child) in leaf_to_root.iter().zip(leaf_to_root.iter().skip(1)) {
            if child.payload().parent.as_ref() != Some(&parent.payload().id)
                || child.payload().issuer != parent.payload().subject
                || !child.payload().is_attenuation_of(parent.payload())
            {
                return Err(CoordinatorError::Refused(
                    "historical delegation chain is not ordered root-to-leaf attenuation"
                        .to_string(),
                ));
            }
        }
        Ok(leaf_to_root)
    }

    /// Verify that a newly admitted delegation is signed by its semantic issuer
    /// and reaches the installed owner through an unrevoked durable chain.
    ///
    /// Installed-key admission establishes that a recognized key signed the
    /// envelope. It does not itself prove that the signer may issue this grant;
    /// that relationship is checked here before the immutable wire is stored.
    pub(crate) fn validate_delegation_authority(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        admitted: &politeia_core::trust::Admitted<Delegation>,
    ) -> Result<(), CoordinatorError> {
        let delegation = admitted.payload();
        if admitted.signer() != &delegation.issuer {
            return Err(CoordinatorError::Refused(
                "delegation envelope signer is not its semantic issuer".to_string(),
            ));
        }
        if durable.owner != self.workspace.owner
            || durable.owner_delegation != self.workspace.owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "durable workspace owner differs from installed workspace skeleton".to_string(),
            ));
        }

        let mut current = delegation.clone();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.id.clone()) {
                return Err(CoordinatorError::Refused(
                    "delegation authority chain contains a cycle".to_string(),
                ));
            }
            match current.parent.as_ref() {
                None => {
                    if current.issuer != self.workspace.owner {
                        return Err(CoordinatorError::Refused(
                            "delegation chain is not rooted in the installed owner".to_string(),
                        ));
                    }
                    return Ok(());
                }
                Some(parent_id) => {
                    let persisted = durable.delegations.get(parent_id).ok_or_else(|| {
                        CoordinatorError::Refused(
                            "delegation parent is not durably admitted".to_string(),
                        )
                    })?;
                    if persisted.revoked {
                        return Err(CoordinatorError::Refused(
                            "delegation parent is revoked".to_string(),
                        ));
                    }
                    let parent = self
                        .anchors
                        .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
                        .map_err(refusal)?;
                    if parent.signer() != &parent.payload().issuer
                        || current.issuer != parent.payload().subject
                        || !current.is_attenuation_of(parent.payload())
                    {
                        return Err(CoordinatorError::Refused(
                            "delegation does not attenuate a signed durable parent".to_string(),
                        ));
                    }
                    current = parent.into_payload();
                }
            }
        }
    }

    async fn commission(&self, value: Value) -> Result<OperationResult, CoordinatorError> {
        let request: CommissioningRequest = serde_json::from_value(value).map_err(|error| {
            CoordinatorError::Refused(format!("commissioning input is not typed JSON: {error}"))
        })?;
        match request {
            CommissioningRequest::RevokeDelegation { request } => {
                self.revoke_delegation_request(request).await
            }
            CommissioningRequest::Generation { request } => self.handle_generation(request).await,
            CommissioningRequest::Learning { request } => self.handle_learning(request).await,
            CommissioningRequest::ApproveClaim {
                candidate,
                approval,
            } => self.approve_candidate(*candidate, approval).await,
            CommissioningRequest::CommissioningApproval { evidence } => {
                self.admit_commissioning_approval(evidence).await
            }
            CommissioningRequest::CapabilityEvidence { submission } => {
                self.admit_capability_evidence(*submission).await
            }
            CommissioningRequest::DetectorCalibrationEvidence { submission } => {
                self.admit_detector_calibration_evidence(*submission).await
            }
            CommissioningRequest::AdmitDelegation { delegation } => {
                let admitted = self
                    .anchors
                    .admit_expected(AdmissionKind::Delegation, (*delegation).clone())
                    .map_err(refusal)?;
                let durable = self.durable_snapshot().await?;
                self.validate_delegation_authority(&durable, &admitted)?;
                let durable_receipt = self
                    .storage
                    .admit_delegation(&self.scope, &admitted, &delegation)
                    .await
                    .map_err(|error| storage_refusal(&error))?;
                let commissioner_grant_digest = CommissionerGrantRecord {
                    institution: self.workspace.institution.clone(),
                    workspace: self.workspace.id.clone(),
                    valid_from: durable_receipt.admitted_at,
                    revoked_at: None,
                    delegation: admitted.payload().clone(),
                }
                .digest()
                .map_err(refusal)?;
                Ok(OperationResult::Coordinated {
                    result: json!({
                        "delegation": admitted.payload().id,
                        "admitted_at": durable_receipt.admitted_at,
                        "commissioner_grant_digest": commissioner_grant_digest,
                        "admitted": true,
                    }),
                    evidence_refs: Vec::new(),
                })
            }
        }
    }
}

impl CommissioningCoordinator for PoliteiadService {
    fn execute(
        &self,
        operation: SemanticOperation,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResult, CoordinatorError>> + Send + '_>> {
        Box::pin(self.handle(operation))
    }
}

#[derive(Clone)]
struct BootstrapCapturePolicy {
    workspace: InstitutionWorkspace,
    captures: TrustedSourceCaptureRegistry,
    capture: politeia_core::SourceCaptureId,
    delegation: politeia_core::trust::Admitted<Delegation>,
    scope: ReconnaissanceScope,
    bootstrap: politeia_core::Digest,
    now: jiff::Timestamp,
}
impl PolicyDecisionPoint for BootstrapCapturePolicy {
    type Error = BootstrapRefusal;
    fn decide(
        &self,
        intent: &OperationIntent,
    ) -> impl Future<Output = Result<politeia_policy::PolicyDecision, Self::Error>> + Send {
        ready((|| {
            let digest =
                politeia_core::Digest::of(politeia_core::DigestDomain::OperationIntent, intent)
                    .map_err(BootstrapRefusal::Encoding)?;
            evaluate_bootstrap_reconnaissance(&BootstrapReconnaissance {
                workspace: &self.workspace,
                captures: &self.captures,
                capture: &self.capture,
                delegation: &self.delegation,
                scope: &self.scope,
                principal: &intent.principal,
                operation: &intent.operation,
                resources: &intent.resources,
                intent_digest: &digest,
                bootstrap_record_digest: &self.bootstrap,
                at: self.now,
            })
        })())
    }
}
#[derive(Debug)]
struct CapturePortError(String);
impl std::fmt::Display for CapturePortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CapturePortError {}
struct InstalledCapturePort {
    root: PathBuf,
    request: SourceCaptureRequest,
    resources: BTreeSet<String>,
    input_digest: Digest,
    audience: String,
}
impl EffectPort for InstalledCapturePort {
    type Output = crate::source::SourceSnapshot;
    type Error = CapturePortError;
    fn adapter(&self) -> &politeia_core::AdapterId {
        &self.request.adapter
    }
    fn audience(&self) -> &str {
        &self.audience
    }
    fn execute<'a>(
        &'a self,
        effect: AuthorizedEffect<'a>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        ready(
            if effect.lease().resources() == &self.resources
                && effect.lease().input_digest() == &self.input_digest
            {
                crate::source::snapshot(crate::source::SourceSnapshotRequest {
                    root: self.root.clone(),
                    members: self.request.manifest.iter().map(PathBuf::from).collect(),
                })
                .map_err(|e| CapturePortError(e.to_string()))
            } else {
                Err(CapturePortError(
                "capture lease resources or authenticated input differ from the installed descriptor"
                    .to_string(),
            ))
            },
        )
    }
}

pub(crate) fn storage_refusal(error: &politeia_storage::StorageError) -> CoordinatorError {
    CoordinatorError::Refused(format!("durable authority refused operation: {error}"))
}

fn runtime_refusal(error: &RuntimeError) -> CoordinatorError {
    CoordinatorError::Refused(format!(
        "durable authorization clock refused operation: {error}"
    ))
}

pub(crate) fn refusal(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::Refused(error.to_string())
}

fn evidence_wire(
    record: &SignedRecord,
) -> Result<SignedAdmissionWire<EvidenceRequest>, CoordinatorError> {
    let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(record.payload())
        .map_err(|error| {
            CoordinatorError::Refused(format!("durable evidence wire is malformed: {error}"))
        })?;
    if wire.signer != *record.signer() || wire.signature != record.signature() {
        return Err(CoordinatorError::Refused(
            "durable evidence wire differs from its stored signature".to_string(),
        ));
    }
    Ok(wire)
}

pub(crate) fn state_wire<T: serde::de::DeserializeOwned>(
    value: &politeia_storage::StoredPayload,
) -> Result<SignedAdmissionWire<T>, CoordinatorError> {
    serde_json::from_slice(&value.bytes).map_err(|error| {
        CoordinatorError::Refused(format!("durable signed state wire is malformed: {error}"))
    })
}

pub(crate) fn signed_wire_record<T: Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<SignedRecord, CoordinatorError> {
    let value = serde_json::to_value(wire).map_err(|error| {
        CoordinatorError::Refused(format!("signed wire encoding failed: {error}"))
    })?;
    SignedRecord::from_json(&value, wire.signer.clone(), wire.signature.clone())
        .map_err(|error| storage_refusal(&error))
}

/// Bind an active-generation operation to exactly the signed capture proof it
/// will authorize. The operational carrier itself is deliberately excluded to
/// avoid a self-referential signed-intent digest.
pub(crate) fn capture_operation_input_digest(
    submission: &SourceCaptureSubmission,
) -> Result<politeia_core::Digest, CoordinatorError> {
    politeia_core::canonical::to_canonical_bytes(&(
        &submission.capture,
        &submission.evidence,
        &submission.observation,
        &submission.reconnaissance,
    ))
    .map(|bytes| politeia_core::Digest::blake3(&bytes))
    .map_err(refusal)
}

fn capture_resources_match(
    descriptor_resources: &BTreeSet<String>,
    intent_resources: &BTreeSet<String>,
) -> bool {
    descriptor_resources == intent_resources
}

#[cfg(test)]
mod capture_tests {
    use std::collections::BTreeSet;

    use super::capture_resources_match;

    #[test]
    fn refuses_a_granted_resource_substituted_for_capture_descriptor_resources() {
        let descriptor = BTreeSet::from([
            "capture-descriptor:expected".to_string(),
            "source:institution-crm".to_string(),
        ]);
        let granted_but_unrelated =
            BTreeSet::from(["source:approved-but-not-captured".to_string()]);
        assert!(!capture_resources_match(
            &descriptor,
            &granted_but_unrelated
        ));
    }
}
