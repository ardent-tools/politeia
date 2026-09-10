//! Installed-owner acceptance of operational custody after commissioner closure.

use std::collections::BTreeSet;

use jiff::Timestamp;
use politeia_core::{
    BudgetReservationId, Delegation, DelegationId, Digest, ExecutionLocality, InstitutionId,
    InstitutionWorkspaceId, PrincipalId, RuntimeGenerationId,
    canonical::to_canonical_bytes,
    commissioning::{
        COMMISSION_ACTION, CommissionerGrantRecord, TrustedCommissionerGrantRegistry,
        commissioning_institution_audience, commissioning_workspace_resource,
    },
    evidence::{EvidenceRequest, IndependenceClass, TrustedEvidenceRegistry},
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use politeia_evidence::{
    HandoffReceipt, commissioner_revocation_subject_digest, operational_continuity_subject_digest,
};
use politeia_runtime::{
    AuthorizationLedger, OperationIntent, routing::ExecutionResourceDescriptor,
};
use politeia_storage::{
    AttemptStatus, CanonicalPayload, EvidenceAdmission, HandoffCommit, PostgresAuthorizationLedger,
    ScopedCommit,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    CoordinatorError, OperationResult,
    service::{PoliteiadService, refusal, signed_wire_record, storage_refusal},
    service_operation::{
        ActiveOperationalRegistry, InstalledOperationHandler, OperationCompletionOutcome,
        OperationReceipt, RESOURCE_MANIFEST_OPERATION, ResourceManifest,
    },
};

/// Exact owner-evidence method accepting complete commissioner closure.
pub const HANDOFF_REVOCATION_METHOD: &str = "politeia.handoff.commissioner-revocation.v1";
/// Exact owner-evidence method accepting post-revocation operational continuity.
pub const HANDOFF_CONTINUITY_METHOD: &str = "politeia.handoff.operational-continuity.v1";
const HANDOFF_RECEIPT_SCHEMA: &str = "politeia.operation-receipt.v1";

/// Owner-signed evidence and durable canary selected for one operational handoff.
///
/// Every field is inert transport input. The daemon derives generation and
/// commissioning provenance from durable state and resolves the canary from
/// the completed operation ledger before constructing a core handoff receipt.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffSubmission {
    /// Active generation the owner expects to accept.
    pub expected_generation: RuntimeGenerationId,
    /// Exact completed operation reservation selected as the continuity canary.
    pub continuity_reservation: BudgetReservationId,
    /// Owner evidence accepting the ended original commissioner grant.
    pub revocation_evidence: SignedAdmissionWire<EvidenceRequest>,
    /// Owner evidence accepting the exact completed operation receipt.
    pub continuity_evidence: SignedAdmissionWire<EvidenceRequest>,
}

struct AuthorityClosure {
    registry: TrustedCommissionerGrantRegistry,
    relevant: BTreeSet<DelegationId>,
    latest_end: Timestamp,
}

impl PoliteiadService {
    /// Derive and durably commit an owner-accepted operational handoff.
    pub(crate) async fn accept_handoff(
        &self,
        submission: HandoffSubmission,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        if durable.owner != self.workspace().owner
            || durable.owner_delegation != self.workspace().owner_delegation
        {
            return Err(handoff_refusal(
                "durable workspace owner differs from the installed owner",
            ));
        }
        let active = durable
            .active_generation
            .clone()
            .ok_or_else(|| handoff_refusal("no operational generation is active"))?;
        if submission.expected_generation.digest() != &active {
            return Err(handoff_refusal(
                "handoff names a generation other than the active generation",
            ));
        }

        let artifact = self.verified_generation(&active).await?;
        let generation = artifact.generation().clone();
        if generation.id() != &submission.expected_generation {
            return Err(handoff_refusal(
                "verified active generation differs from the handoff selection",
            ));
        }
        let generation_inputs = generation.inputs();
        let commissioning_receipt = self
            .load_commissioning_receipt(&durable, &generation_inputs.commissioning_record)
            .await?;
        let commissioning = self
            .commissioning_record(
                &durable,
                &generation_inputs.commissioning_record,
                &generation_inputs.commissioning_record_digest,
                &commissioning_receipt,
            )
            .await?;

        let observed_at =
            PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
                .observed_at()
                .await
                .map_err(|error| handoff_refusal(error.to_string()))?;
        let closure =
            self.authority_closure(&durable, commissioning.commissioner(), observed_at)?;

        let attempt = self
            .storage()
            .load_attempt(self.scope(), &submission.continuity_reservation)
            .await
            .map_err(|error| storage_refusal(&error))?;
        if attempt.status != AttemptStatus::Completed {
            return Err(handoff_refusal(
                "handoff continuity reservation is not durably completed",
            ));
        }
        let receipt_bytes = attempt.receipt_payload.ok_or_else(|| {
            handoff_refusal("handoff continuity attempt has no canonical receipt bytes")
        })?;
        let retained_digest = attempt.receipt_digest.ok_or_else(|| {
            handoff_refusal("handoff continuity attempt has no canonical receipt digest")
        })?;
        if Digest::blake3(&receipt_bytes) != retained_digest {
            return Err(handoff_refusal(
                "handoff continuity receipt bytes differ from the durable digest",
            ));
        }
        let operation_receipt: OperationReceipt =
            serde_json::from_slice(&receipt_bytes).map_err(|error| {
                handoff_refusal(format!("handoff continuity receipt is malformed: {error}"))
            })?;
        let canonical_operation = CanonicalPayload::from_serializable(&operation_receipt)
            .map_err(|error| storage_refusal(&error))?;
        if canonical_operation.bytes() != receipt_bytes
            || canonical_operation.digest() != &retained_digest
        {
            return Err(handoff_refusal(
                "handoff continuity receipt is not exact canonical retained output",
            ));
        }
        let operational_registry = self.operational_registry_for_generation(&active).await?;
        self.validate_continuity_canary(
            &submission,
            &operation_receipt,
            &operational_registry,
            commissioning.commissioner(),
            closure.latest_end,
        )?;

        let evidence = TrustedEvidenceRegistry::admit_signed(
            self.anchors(),
            [
                submission.revocation_evidence.clone(),
                submission.continuity_evidence.clone(),
            ],
        )
        .map_err(refusal)?;
        let revocation = evidence
            .resolve(&submission.revocation_evidence.payload.id)
            .ok_or_else(|| handoff_refusal("handoff revocation evidence is absent"))?;
        let continuity = evidence
            .resolve(&submission.continuity_evidence.payload.id)
            .ok_or_else(|| handoff_refusal("handoff continuity evidence is absent"))?;
        if [revocation, continuity]
            .iter()
            .any(|record| durable.evidence.contains_key(&record.id))
        {
            return Err(handoff_refusal(
                "handoff evidence identity is already durably admitted",
            ));
        }
        let expected_revocation_subject = commissioner_revocation_subject_digest(
            &self.workspace().institution,
            &self.workspace().id,
            commissioning.id(),
            commissioning.commissioner_grant_digest(),
        )
        .map_err(refusal)?;
        let expected_continuity_subject = operational_continuity_subject_digest(
            &self.workspace().institution,
            &self.workspace().id,
            generation.id(),
        )
        .map_err(refusal)?;
        if revocation.subject != expected_revocation_subject
            || revocation.method != HANDOFF_REVOCATION_METHOD
            || revocation.payload_digest != *commissioning.commissioner_grant_digest()
            || continuity.subject != expected_continuity_subject
            || continuity.method != HANDOFF_CONTINUITY_METHOD
            || continuity.payload_digest != retained_digest
        {
            return Err(handoff_refusal(
                "handoff evidence does not bind the exact grant and completed canary receipt",
            ));
        }
        if [revocation, continuity].iter().any(|record| {
            record.producer != self.workspace().owner
                || record.producer_delegation != self.workspace().owner_delegation
                || !matches!(record.independence, IndependenceClass::HumanAuthority)
                || record.observed_at > observed_at
        }) {
            return Err(handoff_refusal(
                "handoff evidence is not current installed-owner human authority",
            ));
        }
        if revocation.observed_at < closure.latest_end
            || continuity.observed_at < operation_receipt.completed_at
            || continuity.observed_at <= revocation.observed_at
        {
            return Err(handoff_refusal(
                "handoff evidence does not follow complete authority closure and canary completion",
            ));
        }

        let continuity_ids = BTreeSet::from([continuity.id.clone()]);
        let handoff_receipt = HandoffReceipt::new(
            self.workspace(),
            &commissioning,
            &generation,
            &closure.registry,
            &evidence,
            &revocation.id,
            &continuity_ids,
        )
        .map_err(refusal)?;
        let canonical_handoff = CanonicalPayload::from_serializable(&handoff_receipt)
            .map_err(|error| storage_refusal(&error))?;
        let owner_authority = self.current_owner_authority(&durable)?;
        let revocation_record = signed_wire_record(&submission.revocation_evidence)?;
        let continuity_record = signed_wire_record(&submission.continuity_evidence)?;
        let committed = self
            .storage()
            .commit_handoff_authorized(
                &HandoffCommit {
                    transition: ScopedCommit {
                        scope: self.scope().clone(),
                        expected_revision: durable.revision,
                        model: durable.model,
                        model_kind: "handoff_receipt".to_string(),
                        transition: continuity_record.clone(),
                        state: Vec::new(),
                        evidence: vec![
                            EvidenceAdmission {
                                id: revocation.id.clone(),
                                record: revocation_record,
                            },
                            EvidenceAdmission {
                                id: continuity.id.clone(),
                                record: continuity_record,
                            },
                        ],
                        outbox: Vec::new(),
                    },
                    generation: active,
                    commissioning_record: commissioning.id().clone(),
                    commissioner: commissioning.commissioner().clone(),
                    expected_authorities: closure.relevant,
                    continuity_reservation: submission.continuity_reservation.clone(),
                    continuity_receipt: canonical_operation,
                    handoff_receipt: canonical_handoff,
                },
                &owner_authority,
            )
            .await
            .map_err(|error| storage_refusal(&error))?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": submission.expected_generation,
                "commissioning_record": commissioning.id(),
                "continuity_reservation": submission.continuity_reservation,
                "continuity_receipt_digest": retained_digest,
                "handoff_receipt_digest": committed.handoff_receipt_digest,
                "handoff": handoff_receipt,
                "revision": committed.revision,
                "transition": committed.transition_digest,
                "accepted_at": committed.accepted_at,
                "completed": true,
            }),
            evidence_refs: vec![
                submission.revocation_evidence.payload.id.0.to_string(),
                submission.continuity_evidence.payload.id.0.to_string(),
            ],
        })
    }

    fn authority_closure(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        original_commissioner: &PrincipalId,
        observed_at: Timestamp,
    ) -> Result<AuthorityClosure, CoordinatorError> {
        let mut relevant = BTreeSet::new();
        let mut commissioner_grants = Vec::new();
        let mut latest_end = None;
        for (id, persisted) in &durable.delegations {
            let admitted = self
                .anchors()
                .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
                .map_err(refusal)?;
            if admitted.signer() != &admitted.payload().issuer {
                return Err(handoff_refusal(
                    "durable authority signer differs from its semantic issuer",
                ));
            }
            let original_authority = admitted.payload().subject == *original_commissioner;
            let commissioner_authority = is_scoped_commissioner_grant(
                admitted.payload(),
                &self.workspace().owner,
                &self.workspace().institution,
                &self.workspace().id,
            );
            if !original_authority && !commissioner_authority {
                continue;
            }
            let historical = self.admit_historical_delegation_chain(
                durable,
                id,
                &admitted.payload().subject,
                persisted.admitted_at,
            )?;
            if historical
                .last()
                .is_none_or(|leaf| leaf.payload() != admitted.payload())
            {
                return Err(handoff_refusal(
                    "recovered commissioner authority differs from its historical chain",
                ));
            }
            relevant.insert(id.clone());
            let authority_end = persisted
                .revoked_at
                .map_or(admitted.payload().expires_at, |revoked| {
                    revoked.min(admitted.payload().expires_at)
                });
            if authority_end > observed_at {
                return Err(handoff_refusal(
                    "commissioner authority remains active for the workspace",
                ));
            }
            latest_end = Some(
                latest_end.map_or(authority_end, |latest: Timestamp| latest.max(authority_end)),
            );
            if commissioner_authority {
                commissioner_grants.push(CommissionerGrantRecord {
                    institution: self.workspace().institution.clone(),
                    workspace: self.workspace().id.clone(),
                    valid_from: persisted.admitted_at,
                    revoked_at: persisted.revoked_at,
                    delegation: admitted.into_payload(),
                });
            }
        }
        let registry = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            observed_at,
            commissioner_grants,
        )
        .map_err(refusal)?;
        if registry.active_count_for(&self.workspace().institution, &self.workspace().id) != 0 {
            return Err(handoff_refusal(
                "commissioner authority remains active for the workspace",
            ));
        }
        let latest_end = latest_end.ok_or_else(|| {
            handoff_refusal("durable authority has no original commissioner grant")
        })?;
        Ok(AuthorityClosure {
            registry,
            relevant,
            latest_end,
        })
    }

    fn current_owner_authority(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
    ) -> Result<Vec<Admitted<Delegation>>, CoordinatorError> {
        let persisted = durable
            .delegations
            .get(&self.workspace().owner_delegation)
            .ok_or_else(|| handoff_refusal("installed owner delegation is not durable"))?;
        let authority = self.admit_durable_delegation_chain(
            durable,
            std::slice::from_ref(&persisted.wire.payload),
            &self.workspace().owner,
        )?;
        let root = authority
            .first()
            .ok_or_else(|| handoff_refusal("installed owner authority is absent"))?;
        if authority.len() != 1
            || root.payload().id != self.workspace().owner_delegation
            || root.payload().issuer != self.workspace().owner
            || root.payload().subject != self.workspace().owner
            || root.payload().parent.is_some()
            || !root.payload().actions.contains(COMMISSION_ACTION)
            || !root
                .payload()
                .resources
                .contains(&commissioning_workspace_resource(&self.workspace().id))
            || !root
                .payload()
                .audience
                .contains(&commissioning_institution_audience(
                    &self.workspace().institution,
                ))
        {
            return Err(handoff_refusal(
                "handoff is not authorized by the installed owner root",
            ));
        }
        Ok(authority)
    }

    fn validate_continuity_canary(
        &self,
        submission: &HandoffSubmission,
        receipt: &OperationReceipt,
        registry: &ActiveOperationalRegistry,
        commissioner: &PrincipalId,
        latest_authority_end: Timestamp,
    ) -> Result<(), CoordinatorError> {
        let admitted_intent = self
            .anchors()
            .admit_expected(AdmissionKind::OperationIntent, receipt.intent.clone())
            .map_err(refusal)?;
        if admitted_intent.signer() != &admitted_intent.payload().principal
            || admitted_intent.payload().principal == *commissioner
        {
            return Err(handoff_refusal(
                "handoff canary is not an independently authenticated operational request",
            ));
        }
        let intent_digest = admitted_intent
            .payload()
            .digest()
            .map_err(|error| handoff_refusal(error.to_string()))?;
        let registered = registry
            .execution()
            .exact_operation(&admitted_intent.payload().operation)
            .ok_or_else(|| {
                handoff_refusal("handoff canary operation differs from the active registry")
            })?;
        if registered.spec.name != RESOURCE_MANIFEST_OPERATION
            || !matches!(
                registered.handler,
                InstalledOperationHandler::ResourceManifest { .. }
            )
        {
            return Err(handoff_refusal(
                "handoff continuity is not the installed deterministic manifest canary",
            ));
        }
        let assignment = receipt
            .routing
            .assignment()
            .map_err(refusal)?
            .ok_or_else(|| handoff_refusal("handoff canary routing selected no resource"))?;
        let resource = registry
            .execution()
            .resource(&assignment.resource)
            .ok_or_else(|| handoff_refusal("handoff canary selected an unknown resource"))?;
        let resource_digest = resource.digest().map_err(refusal)?;
        let availability_digest = receipt.availability.digest().map_err(refusal)?;
        let requirement_digest = registered.requirement.digest().map_err(refusal)?;
        if receipt.schema != HANDOFF_RECEIPT_SCHEMA
            || receipt.institution != self.workspace().institution
            || receipt.workspace != self.workspace().id
            || receipt.generation != *registry.generation()
            || receipt.reservation != submission.continuity_reservation
            || receipt.completed_at <= latest_authority_end
            || receipt.decision.bundle != *registry.policy().bundle()
            || receipt.decision.policy_digest != *registry.policy().digest()
            || receipt.decision.intent_digest != intent_digest
            || receipt.decision.principal != admitted_intent.payload().principal
            || !receipt.decision.allowed
            || assignment != receipt.execution
            || admitted_intent.payload().execution.as_ref() != Some(&assignment)
            || receipt.routing.requirement_digest != requirement_digest
            || receipt.routing.availability_snapshot_digest != availability_digest
            || receipt.availability.available_resources
                != *registry.execution().available_resources()
            || !receipt
                .availability
                .available_resources
                .contains(&assignment.resource)
            || assignment.resource_digest != resource_digest
            || assignment.trust_domain != self.workspace().trust_domain
            || assignment.locality != ExecutionLocality::ClientLocal
            || assignment.adapter != resource.adapter
            || receipt.adapter != resource.adapter
            || !matches!(
                resource.descriptor,
                ExecutionResourceDescriptor::DeterministicTool { .. }
            )
        {
            return Err(handoff_refusal(
                "handoff canary receipt is not a completed active-generation local operation",
            ));
        }
        validate_manifest_outcome(&receipt.outcome, admitted_intent.payload())
    }
}

fn validate_manifest_outcome(
    outcome: &OperationCompletionOutcome,
    intent: &OperationIntent,
) -> Result<(), CoordinatorError> {
    let OperationCompletionOutcome::Succeeded { manifest } = outcome;
    let resources: Vec<_> = intent.resources.iter().cloned().collect();
    let resource_count = u32::try_from(resources.len())
        .map_err(|_| handoff_refusal("handoff canary resource count is unrepresentable"))?;
    let expected_digest = Digest::blake3(
        &to_canonical_bytes(&ResourceManifestSubject {
            schema: "politeia.resource-manifest.v1",
            operation: &intent.operation.id,
            resources: &resources,
        })
        .map_err(refusal)?,
    );
    if manifest
        != &(ResourceManifest {
            operation: intent.operation.id.clone(),
            resources,
            resource_count,
            manifest_digest: expected_digest,
        })
    {
        return Err(handoff_refusal(
            "handoff canary outcome differs from the deterministic manifest result",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ResourceManifestSubject<'a> {
    schema: &'static str,
    operation: &'a politeia_core::OperationId,
    resources: &'a [String],
}

fn is_scoped_commissioner_grant(
    delegation: &Delegation,
    owner: &PrincipalId,
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
) -> bool {
    if delegation.subject == *owner || !delegation.actions.contains(COMMISSION_ACTION) {
        return false;
    }
    let expected_workspace = commissioning_workspace_resource(workspace);
    let workspace_scopes: Vec<_> = delegation
        .resources
        .iter()
        .filter(|resource| resource.starts_with("institution-workspace:"))
        .collect();
    let expected_institution = commissioning_institution_audience(institution);
    let institution_scopes: Vec<_> = delegation
        .audience
        .iter()
        .filter(|audience| audience.starts_with("institution:"))
        .collect();
    workspace_scopes == [&expected_workspace] && institution_scopes == [&expected_institution]
}

fn handoff_refusal(reason: impl Into<String>) -> CoordinatorError {
    CoordinatorError::Refused(format!("operational handoff refused: {}", reason.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use politeia_core::{Digest, OperationId, OperationSpec, PrincipalId, ResourceBudget};
    use politeia_runtime::OperationIntent;
    use serde_json::json;

    use super::{
        HandoffSubmission, OperationCompletionOutcome, ResourceManifest, validate_manifest_outcome,
    };

    #[test]
    fn handoff_submission_cannot_omit_owner_evidence() {
        let value = json!({
            "expected_generation": politeia_core::RuntimeGenerationId::derive(b"generation"),
            "continuity_reservation": politeia_core::BudgetReservationId::new(),
        });
        assert!(serde_json::from_value::<HandoffSubmission>(value).is_err());
    }

    #[test]
    fn caller_asserted_canary_outcome_is_rejected() {
        let operation = OperationSpec {
            id: OperationId::new(),
            name: super::RESOURCE_MANIFEST_OPERATION.to_owned(),
            actions: BTreeSet::new(),
            effects: BTreeSet::new(),
            data_classes: BTreeSet::new(),
            evidence_obligations: vec![],
            execution_requirement: None,
            retryable: true,
            requires_idempotency: true,
        };
        let intent = OperationIntent {
            principal: PrincipalId::new(),
            input_digest: Digest::blake3(b"handoff-canary-input"),
            delegation_chain: vec![],
            operation,
            resources: BTreeSet::from(["public:approved-operation".to_owned()]),
            budget: ResourceBudget {
                wall_ms: Some(1),
                cpu_ms: Some(0),
                memory_bytes: Some(0),
                io_bytes: Some(0),
                network_bytes: Some(0),
                external_cost_microunits: Some(0),
            },
            idempotency_key: Some("handoff-canary".to_owned()),
            execution: None,
        };
        let asserted = OperationCompletionOutcome::Succeeded {
            manifest: ResourceManifest {
                operation: intent.operation.id.clone(),
                resources: vec!["public:caller-asserted".to_owned()],
                resource_count: 1,
                manifest_digest: Digest::blake3(b"caller-asserted"),
            },
        };
        assert!(validate_manifest_outcome(&asserted, &intent).is_err());
    }
}
