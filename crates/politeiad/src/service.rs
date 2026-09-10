//! The scoped application coordinator over installed trust and PostgreSQL.
//!
//! Transport passes opaque documents here. This module is the only place that
//! may admit them, select an internal adapter, or attach durable authority.

use std::{future::Future, pin::Pin};

use politeia_core::{institution::InstitutionWorkspace, trust::InstitutionTrustAnchors};
use politeia_storage::{PostgresStorage, Scope};
use serde_json::json;

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
            SemanticOperation::SnapshotSource { .. } => Err(CoordinatorError::Refused(
                "source capture awaits active-delegation validation before any adapter read"
                    .to_string(),
            )),
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
