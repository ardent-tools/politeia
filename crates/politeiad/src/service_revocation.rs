//! Owner-authenticated revocation through the semantic coordinator.

use politeia_core::{
    DelegationId, Digest, EvidenceId,
    canonical::to_canonical_bytes,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_storage::EvidenceAdmission;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    CoordinatorError, OperationResult,
    service::{PoliteiadService, refusal, signed_wire_record, storage_refusal},
};

/// Exact owner decision to end a delegation in the installed workspace.
///
/// The signed envelope supplies institution, workspace, and owner identity.
/// Its payload binds the immutable delegation bytes, evidence identity, and
/// reason; it cannot revoke an unrelated grant sharing a caller's label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegationRevocationRequest {
    /// Delegation whose authority is ended.
    pub delegation: DelegationId,
    /// BLAKE3 of the exact canonical delegation payload.
    pub delegation_digest: Digest,
    /// Identity under which the signed owner decision is retained as evidence.
    pub evidence: EvidenceId,
    /// Owner's reason for revocation.
    pub reason: String,
}

impl PoliteiadService {
    pub(crate) async fn revoke_delegation_request(
        &self,
        wire: SignedAdmissionWire<DelegationRevocationRequest>,
    ) -> Result<OperationResult, CoordinatorError> {
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Revocation, wire.clone())
            .map_err(refusal)?;
        if admitted.signer() != &self.workspace().owner {
            return Err(CoordinatorError::Refused(
                "only the installed institution owner may revoke authority".to_owned(),
            ));
        }
        let request = admitted.payload();
        if request.reason.trim().is_empty() || request.reason.len() > 4096 {
            return Err(CoordinatorError::Refused(
                "revocation requires a nonempty reason of at most 4096 bytes".to_owned(),
            ));
        }
        let durable = self.durable_snapshot().await?;
        let persisted = durable
            .delegations
            .get(&request.delegation)
            .ok_or_else(|| {
                CoordinatorError::Refused(
                    "revocation delegation is not admitted in this workspace".to_owned(),
                )
            })?;
        let delegation = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        let digest = Digest::blake3(&to_canonical_bytes(delegation.payload()).map_err(refusal)?);
        if digest != request.delegation_digest {
            return Err(CoordinatorError::Refused(
                "revocation does not bind the exact admitted delegation".to_owned(),
            ));
        }
        let receipt = self
            .storage()
            .revoke_with_record(
                self.scope(),
                &request.delegation,
                &digest,
                &EvidenceAdmission {
                    id: request.evidence.clone(),
                    record: signed_wire_record(&wire)?,
                },
            )
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({"delegation": request.delegation, "revoked": true, "revision": receipt.revision, "transition": receipt.transition_digest}),
            evidence_refs: vec![request.evidence.0.to_string()],
        })
    }
}
