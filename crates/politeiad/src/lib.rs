//! Politeiad host configuration, local semantic transport, and source capture.
//!
//! This crate is the application boundary around the Politeia kernel. It does
//! not decide policy, mint authority, or replace durable storage. A configured
//! coordinator joins the authenticated core-admission, policy, dispatcher, and
//! PostgreSQL boundaries; CLI and daemon both call that one coordinator.

#![deny(missing_docs)]

pub mod config;
pub mod source;
pub mod transport;

use serde::{Deserialize, Serialize};

use crate::source::SourceSnapshot;

/// One command whose meaning is independent of the local socket or CLI.
///
/// Mutation variants deliberately carry only a named request document. The
/// coordinator resolves it through typed, signed core APIs before any state
/// changes. This avoids treating JSON transport input as institutional truth.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticOperation {
    /// Inspect one source root using an explicit source membership manifest.
    SnapshotSource {
        /// Explicit, read-only source request.
        request: source::SourceSnapshotRequest,
    },
    /// Initialize the local host trust boundary.
    Initialize {
        /// Location of an authenticated initialization request.
        request_path: String,
    },
    /// Submit a signed commissioning transition for authoritative processing.
    Commissioning {
        /// Location of the signed, typed request document.
        request_path: String,
    },
    /// Ask the active generation to perform a mediated operation.
    Operate {
        /// Location of the typed operation-intent document.
        request_path: String,
    },
    /// Return current state from the durable authority.
    Status,
}

/// A semantic operation's evidence-bearing result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationResult {
    /// A source was read without mutation. Admission remains a coordinator act.
    SourceSnapshot {
        /// Captured source identity and explicit member set.
        snapshot: SourceSnapshot,
    },
    /// A coordinator-produced result, represented as its canonical JSON view.
    Coordinated {
        /// The coordinator's exact result document.
        result: serde_json::Value,
        /// Evidence references emitted by the coordinator.
        evidence_refs: Vec<String>,
    },
}

/// Application-level coordinator for all stateful semantic work.
///
/// Implementations must delegate signed admission to `politeia-core`, policy
/// decisions to `politeia-policy`, protected effects to `politeia-runtime`, and
/// durable commits to `politeia-storage`. It exists so neither transport owns
/// an alternate lifecycle implementation.
pub trait CommissioningCoordinator: Send + Sync {
    /// Execute one non-snapshot semantic operation.
    fn execute(&self, operation: SemanticOperation) -> Result<OperationResult, CoordinatorError>;
}

/// A coordinator refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoordinatorError {
    /// No authoritative coordinator was installed in this host process.
    Unavailable,
    /// The coordinator rejected the exact semantic request.
    Refused(String),
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => {
                formatter.write_str("no authoritative commissioning coordinator is installed")
            }
            Self::Refused(reason) => write!(formatter, "semantic operation refused: {reason}"),
        }
    }
}

impl std::error::Error for CoordinatorError {}

/// Execute a semantic operation through the only application boundary.
///
/// Source inspection is intentionally the one local operation: it only reads
/// an explicit manifest. Its result cannot become an institutional observation
/// until a signed coordinator request admits it.
pub fn execute(
    coordinator: &dyn CommissioningCoordinator,
    operation: SemanticOperation,
) -> Result<OperationResult, CoordinatorError> {
    match operation {
        SemanticOperation::SnapshotSource { request } => source::snapshot(request)
            .map(|snapshot| OperationResult::SourceSnapshot { snapshot })
            .map_err(|error| CoordinatorError::Refused(error.to_string())),
        operation => coordinator.execute(operation),
    }
}

/// A deliberate fail-closed coordinator for hosts not yet fully configured.
#[derive(Debug, Default)]
pub struct UnavailableCoordinator;

impl CommissioningCoordinator for UnavailableCoordinator {
    fn execute(&self, _operation: SemanticOperation) -> Result<OperationResult, CoordinatorError> {
        Err(CoordinatorError::Unavailable)
    }
}
