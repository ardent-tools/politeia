//! Politeiad host configuration, local semantic transport, and source capture.
//!
//! This crate is the application boundary around the Politeia kernel. It does
//! not decide policy, mint authority, or replace durable storage. A configured
//! coordinator joins the authenticated core-admission, policy, dispatcher, and
//! PostgreSQL boundaries; CLI and daemon both call that one coordinator.

#![deny(missing_docs)]

pub mod artifacts;
pub mod cli;
pub mod config;
pub mod learning;
pub mod service;
pub mod service_generation;
pub mod service_learning;
pub mod service_revocation;
pub mod source;
pub mod transport;

use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

use crate::source::SourceSnapshot;

/// One command whose meaning is independent of the local socket or CLI.
///
/// Mutation variants deliberately carry only a named request document. The
/// coordinator resolves it through typed, signed core APIs before any state
/// changes. This avoids treating JSON transport input as institutional truth.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticOperation {
    /// Request an authenticated bounded source capture.
    SnapshotSource {
        /// Signed, typed coordinator input. It has no authority until admitted.
        request: serde_json::Value,
    },
    /// Initialize the local host trust boundary.
    Initialize {
        /// Signed, typed coordinator input. It has no authority until admitted.
        request: serde_json::Value,
    },
    /// Submit a signed commissioning transition for authoritative processing.
    Commissioning {
        /// Signed, typed coordinator input. It has no authority until admitted.
        request: serde_json::Value,
    },
    /// Ask the active generation to perform a mediated operation.
    Operate {
        /// Signed, typed coordinator input. It has no authority until admitted.
        request: serde_json::Value,
    },
    /// Return current state from the durable authority.
    Status,
}

/// A semantic operation's evidence-bearing result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationResult {
    /// A coordinator-authorized source capture.
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
    /// Execute one semantic operation.
    fn execute(
        &self,
        operation: SemanticOperation,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResult, CoordinatorError>> + Send + '_>>;
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
/// Transport input does not receive a local exception. The coordinator admits
/// every request, checks its bounded grant, and invokes adapters only after
/// those checks succeed.
pub async fn execute(
    coordinator: &dyn CommissioningCoordinator,
    operation: SemanticOperation,
) -> Result<OperationResult, CoordinatorError> {
    coordinator.execute(operation).await
}

/// A deliberate fail-closed coordinator for hosts not yet fully configured.
#[derive(Debug, Default)]
pub struct UnavailableCoordinator;

impl CommissioningCoordinator for UnavailableCoordinator {
    fn execute(
        &self,
        _operation: SemanticOperation,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResult, CoordinatorError>> + Send + '_>> {
        Box::pin(async { Err(CoordinatorError::Unavailable) })
    }
}
