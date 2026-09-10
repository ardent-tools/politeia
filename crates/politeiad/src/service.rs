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
    Delegation,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    institution::{InstitutionBoundary, InstitutionWorkspace},
    knowledge::{
        ObservationRequest, SourceCaptureRequest, TrustedObservationRegistry,
        TrustedSourceCaptureRegistry,
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
    EvidenceAdmission, PostgresAuthorizationLedger, PostgresStorage, Scope, ScopedCommit,
    SignedRecord, StateMutation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CommissioningCoordinator, CoordinatorError, OperationResult, SemanticOperation,
    config::InstallationLayout,
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
            SemanticOperation::SnapshotSource { request } => self.capture_source(request).await,
            SemanticOperation::Initialize { .. } => Err(CoordinatorError::Refused(
                "initialization is a local host trust-anchor action, not a running-daemon request"
                    .to_string(),
            )),
            SemanticOperation::Commissioning { request } => self.commission(request).await,
            SemanticOperation::Operate { .. } => Err(CoordinatorError::Refused(
                "operational execution requires a configured dispatcher and active generation"
                    .to_string(),
            )),
        }
    }

    async fn status(&self) -> Result<OperationResult, CoordinatorError> {
        let active_generation = self
            .storage
            .load_active_generation(&self.scope)
            .await
            .map_err(|error| storage_refusal(&error))?
            .map(|digest| digest.as_str().to_string());
        Ok(OperationResult::Coordinated {
            result: json!({
                "institution": self.workspace.institution,
                "workspace": self.workspace.id,
                "trust_domain": self.workspace.trust_domain,
                "active_generation": active_generation,
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
        let now = PostgresAuthorizationLedger::new(self.storage.clone(), self.scope.clone())
            .observed_at()
            .await
            .map_err(|error| runtime_refusal(&error))?;
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
            audience: format!("institution:{}", self.workspace.institution.0),
        };
        let dispatcher = Dispatcher::new(
            policy,
            port,
            PostgresAuthorizationLedger::for_bootstrap(
                self.storage.clone(),
                self.scope.clone(),
                bootstrap.digest().clone(),
            ),
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
            .commit(&ScopedCommit {
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
            })
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
        Ok(admitted)
    }

    /// Verify that a newly admitted delegation is signed by its semantic issuer
    /// and reaches the installed owner through an unrevoked durable chain.
    ///
    /// Installed-key admission establishes that a recognized key signed the
    /// envelope. It does not itself prove that the signer may issue this grant;
    /// that relationship is checked here before the immutable wire is stored.
    fn validate_delegation_authority(
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
                    if current.id != self.workspace.owner_delegation
                        || current.issuer != self.workspace.owner
                    {
                        return Err(CoordinatorError::Refused(
                            "delegation chain is not rooted in the installed owner grant"
                                .to_string(),
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
            CommissioningRequest::AdmitDelegation { delegation } => {
                let admitted = self
                    .anchors
                    .admit_expected(AdmissionKind::Delegation, (*delegation).clone())
                    .map_err(refusal)?;
                let durable = self.durable_snapshot().await?;
                self.validate_delegation_authority(&durable, &admitted)?;
                self.storage
                    .admit_delegation(&self.scope, &admitted, &delegation)
                    .await
                    .map_err(|error| storage_refusal(&error))?;
                Ok(OperationResult::Coordinated {
                    result: json!({
                        "delegation": admitted.payload().id,
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
        ready(if effect.lease().resources() != &self.resources {
            Err(CapturePortError(
                "capture lease resources differ from installed descriptor".to_string(),
            ))
        } else {
            crate::source::snapshot(crate::source::SourceSnapshotRequest {
                root: self.root.clone(),
                members: self.request.manifest.iter().map(PathBuf::from).collect(),
            })
            .map_err(|e| CapturePortError(e.to_string()))
        })
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

pub(crate) fn signed_wire_record<T: Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<SignedRecord, CoordinatorError> {
    let value = serde_json::to_value(wire).map_err(|error| {
        CoordinatorError::Refused(format!("signed wire encoding failed: {error}"))
    })?;
    SignedRecord::from_json(&value, wire.signer.clone(), wire.signature.clone())
        .map_err(|error| storage_refusal(&error))
}
