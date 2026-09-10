//! The scoped application coordinator over installed trust and PostgreSQL.
//!
//! Transport passes opaque documents here. This module is the only place that
//! may admit them, select an internal adapter, or attach durable authority.

use std::{collections::BTreeSet, future::Future, path::PathBuf, pin::Pin};

use politeia_core::{
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    institution::{InstitutionBoundary, InstitutionWorkspace},
    knowledge::{
        ObservationRequest, SourceCaptureRequest, TrustedObservationRegistry,
        TrustedSourceCaptureRegistry,
    },
    reconnaissance::ReconnaissanceScope,
    trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire},
};
use politeia_runtime::{AuthorizationLedger, RuntimeError};
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

impl PoliteiadService {
    /// Connect to PostgreSQL for an already-installed host configuration.
    ///
    /// This does not initialize a host, run migrations, or bootstrap a
    /// workspace. Those are separate explicit host-trust actions.
    pub async fn connect(
        layout: InstallationLayout,
        workspace: InstitutionWorkspace,
        anchors: InstitutionTrustAnchors,
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
        let scope = Scope::new(
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.trust_domain.clone(),
        );
        let storage = PostgresStorage::connect(database_url)
            .await
            .map_err(storage_refusal)?;
        Ok(Self {
            layout,
            workspace,
            anchors,
            storage,
            scope,
        })
    }

    /// Apply PostgreSQL migrations as part of an explicit host setup action.
    pub async fn migrate(&self) -> Result<(), CoordinatorError> {
        self.storage.migrate().await.map_err(storage_refusal)
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
            SemanticOperation::Commissioning { .. } => Err(CoordinatorError::Refused(
                "commissioning request handling is not configured for this installed service"
                    .to_string(),
            )),
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
            .map_err(storage_refusal)?
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
            .map_err(storage_refusal)?;
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
            .map_err(runtime_refusal)?;
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

        let snapshot = crate::source::snapshot(crate::source::SourceSnapshotRequest {
            root: self.layout.workspace_dir.clone(),
            members: request
                .manifest
                .iter()
                .map(PathBuf::from)
                .collect::<BTreeSet<_>>(),
        })
        .map_err(refusal)?;
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
            .map_err(storage_refusal)?;
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
}

impl CommissioningCoordinator for PoliteiadService {
    fn execute(
        &self,
        operation: SemanticOperation,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResult, CoordinatorError>> + Send + '_>> {
        Box::pin(self.handle(operation))
    }
}

fn storage_refusal(error: politeia_storage::StorageError) -> CoordinatorError {
    CoordinatorError::Refused(format!("durable authority refused operation: {error}"))
}

fn runtime_refusal(error: RuntimeError) -> CoordinatorError {
    CoordinatorError::Refused(format!(
        "durable authorization clock refused operation: {error}"
    ))
}

fn refusal(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::Refused(error.to_string())
}

fn signed_wire_record<T: Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<SignedRecord, CoordinatorError> {
    let value = serde_json::to_value(wire).map_err(|error| {
        CoordinatorError::Refused(format!("signed wire encoding failed: {error}"))
    })?;
    SignedRecord::from_json(&value, wire.signer.clone(), wire.signature.clone())
        .map_err(storage_refusal)
}
