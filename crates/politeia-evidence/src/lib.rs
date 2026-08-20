//! politeia-evidence: evidence, verification, and attestation records.
//!
//! Evidence carries claims; attestation binds a verified subject to the exact
//! policy, runtime, adapter, and delegation identities it was verified under.

#![deny(missing_docs)]

use std::collections::BTreeSet;

use politeia_core::{
    AdapterId, CommissioningRecordId, DelegationId, Digest, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId, RuntimeGenerationId,
    generation::{RuntimeGeneration, RuntimeGenerationError},
    institution::InstitutionWorkspace,
    lifecycle::LifecycleProfile,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use politeia_core::{
    commissioning::{CommissioningApproval, CommissioningRecord, TrustedCommissionerGrantRegistry},
    evidence::{EvidenceRecord, EvidenceRegistryError, IndependenceClass, TrustedEvidenceRegistry},
};

#[derive(Serialize)]
struct CommissionerRevocationSubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    commissioning_record: &'a CommissioningRecordId,
    commissioner_grant_digest: &'a Digest,
}

#[derive(Serialize)]
struct OperationalContinuitySubject<'a> {
    kind: &'static str,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    generation: &'a RuntimeGenerationId,
}

/// Digest the exact subject that proves one commissioner delegation ended.
///
/// # Errors
///
/// Returns the JSON encoding failure if the typed subject cannot be represented.
///
/// Time: O(n). Space: O(n), where n is the encoded subject size.
pub fn commissioner_revocation_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    commissioning_record: &CommissioningRecordId,
    commissioner_grant_digest: &Digest,
) -> Result<Digest, serde_json::Error> {
    serde_json::to_vec(&CommissionerRevocationSubject {
        kind: "commissioner_revocation_v1",
        institution,
        workspace,
        commissioning_record,
        commissioner_grant_digest,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// Digest the exact subject that proves an operational generation remained live.
///
/// # Errors
///
/// Returns the JSON encoding failure if the typed subject cannot be represented.
///
/// Time: O(n). Space: O(n), where n is the encoded subject size.
pub fn operational_continuity_subject_digest(
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    generation: &RuntimeGenerationId,
) -> Result<Digest, serde_json::Error> {
    serde_json::to_vec(&OperationalContinuitySubject {
        kind: "operational_continuity",
        institution,
        workspace,
        generation,
    })
    .map(|bytes| Digest::blake3(&bytes))
}

/// An independent or designated evaluation of evidence against a subject.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// Digest of the verified subject.
    pub subject: Digest,
    /// The verifying principal.
    pub verifier: PrincipalId,
    /// The evidence records the verdict relies on.
    pub evidence: Vec<EvidenceId>,
    /// Whether the subject passed.
    pub passed: bool,
    /// The verifier's independence class.
    pub independence: IndependenceClass,
}

/// A durable statement binding a verified subject to the exact policy,
/// runtime, adapter, delegation, and evidence identities it was verified
/// under. An attestation is not portable to another subject.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// Digest of the attested subject.
    pub subject: Digest,
    /// The attesting verifier.
    pub verifier: PrincipalId,
    /// The policy bundle identity.
    pub policy: PolicyBundleId,
    /// The runtime generation identity.
    pub runtime: RuntimeGenerationId,
    /// The adapter identity.
    pub adapter: AdapterId,
    /// The delegation identity the work ran under.
    pub delegation: DelegationId,
    /// The evidence records bound into the attestation.
    pub evidence: Vec<EvidenceId>,
    /// Digest of the full attestation statement.
    pub statement_digest: Digest,
}

/// Evidence-bearing completion of operational handoff and commissioner revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffReceipt {
    /// Institution whose operation was handed off.
    institution: InstitutionId,
    /// Preserved client-owned workspace.
    workspace: InstitutionWorkspaceId,
    /// Digest of the preserved workspace snapshot.
    workspace_digest: Digest,
    /// Commissioning record incorporated into the generation.
    commissioning_record: CommissioningRecordId,
    /// Digest of that exact commissioning record.
    commissioning_record_digest: Digest,
    /// Activated operational runtime generation.
    generation: RuntimeGenerationId,
    /// Commissioner whose temporary authority was revoked or expired.
    commissioner: PrincipalId,
    /// Revoked/expired commissioner delegation.
    revoked_delegation: DelegationId,
    /// Digest of the complete revoked commissioner grant.
    revoked_grant_digest: Digest,
    /// Evidence proving that commissioner authority was revoked or expired.
    revocation_evidence: EvidenceRecord,
    /// Client principal accepting custody and continuity responsibility.
    accepted_by: PrincipalId,
    /// Exact delegation carrying the accepting client's handoff authority.
    acceptance_delegation: DelegationId,
    /// Evidence that the operational generation remained functional afterward.
    continuity_evidence: Vec<EvidenceRecord>,
    /// Known unresolved obligations retained rather than narrated away.
    unresolved_obligations: BTreeSet<String>,
    /// Digest of the exact owner-approved obligation set.
    unresolved_obligations_digest: Digest,
}

/// A handoff claim was hollow or inconsistent with its resolved provenance.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandoffError {
    /// Workspace, commissioning record, or generation provenance disagreed.
    Provenance(RuntimeGenerationError),
    /// Post-revocation operational continuity had no evidence.
    MissingContinuityEvidence,
    /// One requested evidence identity was absent from trusted admission.
    EvidenceNotAdmitted,
    /// Revocation or continuity evidence was bound to another subject.
    EvidenceSubjectMismatch,
    /// Handoff evidence was not produced by the institution owner accepting custody.
    EvidenceProducerMismatch,
    /// Handoff evidence was produced under another owner delegation.
    EvidenceDelegationMismatch,
    /// The trusted grant store did not contain the exact ended commissioner grant.
    GrantStateMismatch,
    /// At least one commissioner grant remained active for the workspace.
    CommissionerAuthorityStillActive,
    /// Handoff evidence was not admitted as institution-owner authority evidence.
    EvidenceClassMismatch,
    /// Continuity was observed before commissioner revocation.
    ContinuityPrecedesRevocation,
    /// Handoff subject encoding failed.
    Encoding(serde_json::Error),
    /// Handoff did not bind an operational generation.
    NonOperationalGeneration,
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provenance(source) => {
                write!(formatter, "handoff provenance is invalid: {source}")
            }
            Self::MissingContinuityEvidence => {
                formatter.write_str("handoff lacks post-revocation continuity evidence")
            }
            Self::EvidenceNotAdmitted => {
                formatter.write_str("handoff evidence was not admitted by the trusted store")
            }
            Self::EvidenceSubjectMismatch => {
                formatter.write_str("handoff evidence names a different revocation or generation")
            }
            Self::EvidenceProducerMismatch => {
                formatter.write_str("handoff evidence was not produced by the workspace owner")
            }
            Self::EvidenceDelegationMismatch => {
                formatter.write_str("handoff evidence used the wrong owner delegation")
            }
            Self::GrantStateMismatch => {
                formatter.write_str("handoff grant state does not prove revocation or expiry")
            }
            Self::CommissionerAuthorityStillActive => {
                formatter.write_str("commissioner authority remains active after handoff")
            }
            Self::EvidenceClassMismatch => {
                formatter.write_str("handoff evidence lacks human-authority admission")
            }
            Self::ContinuityPrecedesRevocation => {
                formatter.write_str("continuity evidence predates commissioner revocation")
            }
            Self::Encoding(_) => formatter.write_str("handoff evidence subject cannot be encoded"),
            Self::NonOperationalGeneration => {
                formatter.write_str("handoff generation is not operational")
            }
        }
    }
}

impl std::error::Error for HandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provenance(source) => Some(source),
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}

impl HandoffReceipt {
    /// Validate and construct the completion record for client handoff.
    ///
    /// The receipt is intentionally not deserializable directly: untrusted wire
    /// input must first resolve the exact workspace, commissioning record, and
    /// runtime generation and then pass this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError`] when provenance axes disagree, the generation is
    /// not operational, or exact trusted revocation/continuity evidence is
    /// absent, mismatched, or temporally unordered.
    ///
    /// Time: O(e log e). Space: O(e), where e is continuity evidence count.
    #[expect(
        clippy::too_many_arguments,
        reason = "handoff binds seven independent authority, provenance, and evidence inputs"
    )]
    pub fn new(
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        generation: &RuntimeGeneration,
        trusted_grants: &TrustedCommissionerGrantRegistry,
        trusted_evidence: &TrustedEvidenceRegistry,
        revocation_evidence: &EvidenceId,
        continuity_evidence: &BTreeSet<EvidenceId>,
    ) -> Result<Self, HandoffError> {
        generation
            .resolve_provenance(workspace, commissioning)
            .map_err(HandoffError::Provenance)?;
        if generation.inputs().approved.lifecycle != LifecycleProfile::Operational {
            return Err(HandoffError::NonOperationalGeneration);
        }
        if continuity_evidence.is_empty() {
            return Err(HandoffError::MissingContinuityEvidence);
        }
        let revocation = trusted_evidence
            .resolve(revocation_evidence)
            .ok_or(HandoffError::EvidenceNotAdmitted)?;
        let expected_revocation = commissioner_revocation_subject_digest(
            &workspace.institution,
            &workspace.id,
            commissioning.id(),
            commissioning.commissioner_grant_digest(),
        )
        .map_err(HandoffError::Encoding)?;
        if revocation.subject != expected_revocation {
            return Err(HandoffError::EvidenceSubjectMismatch);
        }
        if revocation.producer != workspace.owner {
            return Err(HandoffError::EvidenceProducerMismatch);
        }
        if revocation.producer_delegation != workspace.owner_delegation {
            return Err(HandoffError::EvidenceDelegationMismatch);
        }
        if !matches!(&revocation.independence, IndependenceClass::HumanAuthority) {
            return Err(HandoffError::EvidenceClassMismatch);
        }
        let current_grant = trusted_grants
            .resolve(commissioning.commissioner_delegation())
            .ok_or(HandoffError::GrantStateMismatch)?;
        let current_grant_digest = current_grant.digest().map_err(HandoffError::Encoding)?;
        let authority_ended_at = current_grant.authority_ended_at();
        if current_grant_digest != *commissioning.commissioner_grant_digest()
            || trusted_grants.as_of() < revocation.observed_at
            || revocation.observed_at < authority_ended_at
            || authority_ended_at <= commissioning.captured_at()
        {
            return Err(HandoffError::GrantStateMismatch);
        }
        if trusted_grants.active_count_for(&workspace.institution, &workspace.id) != 0 {
            return Err(HandoffError::CommissionerAuthorityStillActive);
        }
        let all_authority_ended_at = trusted_grants
            .latest_authority_end_for(&workspace.institution, &workspace.id)
            .ok_or(HandoffError::GrantStateMismatch)?;
        let expected_continuity = operational_continuity_subject_digest(
            &workspace.institution,
            &workspace.id,
            generation.id(),
        )
        .map_err(HandoffError::Encoding)?;
        let continuity = continuity_evidence
            .iter()
            .map(|id| {
                trusted_evidence
                    .resolve(id)
                    .ok_or(HandoffError::EvidenceNotAdmitted)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if continuity
            .iter()
            .any(|record| record.subject != expected_continuity)
        {
            return Err(HandoffError::EvidenceSubjectMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.producer != workspace.owner)
        {
            return Err(HandoffError::EvidenceProducerMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.producer_delegation != workspace.owner_delegation)
        {
            return Err(HandoffError::EvidenceDelegationMismatch);
        }
        if continuity
            .iter()
            .any(|record| !matches!(&record.independence, IndependenceClass::HumanAuthority))
        {
            return Err(HandoffError::EvidenceClassMismatch);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at <= revocation.observed_at)
        {
            return Err(HandoffError::ContinuityPrecedesRevocation);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at <= all_authority_ended_at)
        {
            return Err(HandoffError::CommissionerAuthorityStillActive);
        }
        if continuity
            .iter()
            .any(|record| record.observed_at > trusted_grants.as_of())
        {
            return Err(HandoffError::GrantStateMismatch);
        }
        Ok(Self {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            workspace_digest: commissioning.workspace_digest().clone(),
            commissioning_record: commissioning.id().clone(),
            commissioning_record_digest: generation.inputs().commissioning_record_digest.clone(),
            generation: generation.id().clone(),
            commissioner: commissioning.commissioner().clone(),
            revoked_delegation: commissioning.commissioner_delegation().clone(),
            revoked_grant_digest: commissioning.commissioner_grant_digest().clone(),
            revocation_evidence: revocation.clone(),
            accepted_by: workspace.owner.clone(),
            acceptance_delegation: workspace.owner_delegation.clone(),
            continuity_evidence: continuity.into_iter().cloned().collect(),
            unresolved_obligations: commissioning.unresolved_obligations().clone(),
            unresolved_obligations_digest: commissioning.unresolved_obligations_digest().clone(),
        })
    }
}

#[cfg(test)]
mod commissioning_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use jiff::{SignedDuration, Timestamp};
    use politeia_core::{
        DataClass, Delegation, Effect, ResourceBudget,
        commissioning::{
            ApprovedCommissioningSubject, CommissionerGrantRecord,
            TrustedCommissionerGrantRegistry, commissioning_approval_subject_digest,
            commissioning_institution_audience, commissioning_observation_set_digest,
            commissioning_observation_subject_digest, commissioning_workspace_resource,
            unresolved_obligations_digest,
        },
        generation::{
            ApprovedGenerationInputs, CommissioningCapability, ReproducibilityContract,
            RuntimeGenerationInputs,
        },
        lifecycle::DeploymentTopology,
    };

    use super::*;

    #[expect(
        clippy::expect_used,
        reason = "workspace fixtures require one canonical trust-domain identifier"
    )]
    fn workspace() -> InstitutionWorkspace {
        let approved_generation = ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Operational,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::from([("operation".to_string(), Digest::blake3(b"schema"))]),
            adapter_digests: BTreeMap::new(),
            pack_digests: BTreeMap::new(),
            component_digests: BTreeMap::from([(
                "politeiad".to_string(),
                Digest::blake3(b"executable"),
            )]),
            excluded_commissioning_capabilities: BTreeSet::from([
                CommissioningCapability::GenericReconnaissance,
                CommissioningCapability::InstitutionAuthoring,
                CommissioningCapability::AdapterDevelopment,
                CommissioningCapability::PolicyAuthoring,
                CommissioningCapability::GenerationDerivation,
            ]),
            specializer_digest: Digest::blake3(b"specializer"),
            toolchain_digest: Digest::blake3(b"toolchain"),
            reproducibility: ReproducibilityContract::Deterministic,
        };
        InstitutionWorkspace {
            id: InstitutionWorkspaceId::new(),
            institution: InstitutionId::new(),
            trust_domain: "client-a:production"
                .parse()
                .expect("fixture trust domain is canonical"),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"approved model"),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            approved_generation,
            secret_references: BTreeSet::new(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "commissioning fixtures require exact owner-bound approvals"
    )]
    fn record(workspace: &InstitutionWorkspace) -> CommissioningRecord {
        let as_of = Timestamp::now();
        let commissioner = PrincipalId::new();
        let delegation = Delegation {
            id: DelegationId::new(),
            issuer: workspace.owner.clone(),
            subject: commissioner.clone(),
            parent: Some(workspace.owner_delegation.clone()),
            actions: BTreeSet::from(["commission".to_string()]),
            resources: BTreeSet::from([commissioning_workspace_resource(&workspace.id)]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from([commissioning_institution_audience(&workspace.institution)]),
            expires_at: as_of + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        };
        let grant = CommissionerGrantRecord {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            valid_from: as_of - SignedDuration::from_mins(1),
            revoked_at: None,
            delegation: delegation.clone(),
        };
        let grant_digest = grant.digest().expect("fixture grant encodes");
        let observation = EvidenceRecord {
            id: EvidenceId::new(),
            subject: commissioning_observation_subject_digest(
                &workspace.institution,
                &workspace.id,
                &grant_digest,
                &Digest::blake3(b"observation payload"),
            )
            .expect("fixture observation subject encodes"),
            producer: commissioner,
            producer_delegation: delegation.id.clone(),
            method: "bounded read-only discovery".to_string(),
            payload_digest: Digest::blake3(b"observation payload"),
            observed_at: as_of - SignedDuration::from_secs(30),
            independence: IndependenceClass::SelfReported,
        };
        let observation_set_digest =
            commissioning_observation_set_digest(std::slice::from_ref(&observation))
                .expect("fixture observation set encodes");
        let obligations = BTreeSet::from(["document legacy retention".to_string()]);
        let subjects = [
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: workspace
                    .approved_generation
                    .digest()
                    .expect("fixture generation plan encodes"),
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest(
                    &workspace.institution,
                    &workspace.id,
                    &obligations,
                )
                .expect("fixture obligations encode"),
            },
        ];
        let approvals: Vec<_> = subjects
            .iter()
            .map(|subject| EvidenceRecord {
                id: EvidenceId::new(),
                subject: commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    subject,
                    &observation_set_digest,
                )
                .expect("fixture approval subject encodes"),
                producer: workspace.owner.clone(),
                producer_delegation: workspace.owner_delegation.clone(),
                method: "institution-owner approval".to_string(),
                payload_digest: Digest::blake3(b"signed owner approval"),
                observed_at: as_of - SignedDuration::from_secs(10),
                independence: IndependenceClass::HumanAuthority,
            })
            .collect();
        let observation_ids = BTreeSet::from([observation.id.clone()]);
        let approval_ids = approvals
            .iter()
            .map(|approval| approval.id.clone())
            .collect();
        let trusted_evidence = TrustedEvidenceRegistry::from_trusted_bootstrap(
            std::iter::once(observation).chain(approvals),
        )
        .expect("fixture evidence identities are unique");
        let trusted_grants =
            TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [grant])
                .expect("fixture grant is active and unique");
        CommissioningRecord::new(
            workspace,
            &trusted_grants,
            &trusted_evidence,
            &observation_ids,
            &approval_ids,
            obligations,
        )
        .expect("fixture commissioning record is complete")
    }

    #[expect(
        clippy::expect_used,
        reason = "generation fixtures require exact workspace and commissioning digests"
    )]
    fn generation(
        workspace: &InstitutionWorkspace,
        record: &CommissioningRecord,
    ) -> RuntimeGeneration {
        let inputs = RuntimeGenerationInputs {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            workspace_digest: workspace.digest().expect("fixture workspace encodes"),
            trust_domain: workspace.trust_domain.clone(),
            policy_bundle: workspace.policy_bundle.clone(),
            policy_digest: workspace.policy_digest.clone(),
            commissioning_record: record.id().clone(),
            commissioning_record_digest: record.digest().expect("fixture record encodes"),
            approved: workspace.approved_generation.clone(),
        };
        RuntimeGeneration::derive(inputs, workspace, record)
            .expect("fixture generation provenance is coherent")
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "empty trusted fixture registries must remain constructible"
    )]
    fn commissioning_without_trusted_authority_is_rejected() {
        let workspace = workspace();
        let as_of = Timestamp::now();
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [])
            .expect("empty trusted grant snapshot is coherent");
        let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap([])
            .expect("empty trusted evidence registry is coherent");
        assert!(
            CommissioningRecord::new(
                &workspace,
                &grants,
                &evidence,
                &BTreeSet::from([EvidenceId::new()]),
                &BTreeSet::new(),
                BTreeSet::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn generation_rejects_a_commissioning_record_from_another_client() {
        let client_a = workspace();
        let record_a = record(&client_a);
        let valid = generation(&client_a, &record_a);
        let client_b = workspace();
        let record_b = record(&client_b);

        assert!(matches!(
            valid.resolve_provenance(&client_a, &record_b),
            Err(RuntimeGenerationError::ProvenanceMismatch { .. })
        ));
    }

    fn evidence(
        id: EvidenceId,
        subject: Digest,
        producer: PrincipalId,
        producer_delegation: DelegationId,
        observed_at: Timestamp,
    ) -> EvidenceRecord {
        EvidenceRecord {
            id,
            subject,
            producer,
            producer_delegation,
            method: "client-owned acceptance probe".to_string(),
            payload_digest: Digest::blake3(b"probe receipt"),
            observed_at,
            independence: IndependenceClass::HumanAuthority,
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "handoff evidence fixtures must resolve exact canonical subjects"
    )]
    fn handoff_requires_admitted_client_evidence_after_revocation() {
        let workspace = workspace();
        let record = record(&workspace);
        let generation = generation(&workspace, &record);
        let revoked_at = Timestamp::now();
        let continuity_at = revoked_at + SignedDuration::from_secs(1);
        let mut ended_grant = record.commissioner_grant().clone();
        ended_grant.revoked_at = Some(revoked_at);
        let handoff_grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            continuity_at,
            [ended_grant.clone()],
        )
        .expect("trusted handoff snapshot records the exact revoked grant");
        let revocation_id = EvidenceId::new();
        let continuity_id = EvidenceId::new();
        let revocation_subject = commissioner_revocation_subject_digest(
            &workspace.institution,
            &workspace.id,
            record.id(),
            record.commissioner_grant_digest(),
        )
        .expect("revocation subject encodes");
        let continuity_subject = operational_continuity_subject_digest(
            &workspace.institution,
            &workspace.id,
            generation.id(),
        )
        .expect("continuity subject encodes");
        let equal_time_registry = TrustedEvidenceRegistry::from_trusted_bootstrap([
            evidence(
                revocation_id.clone(),
                revocation_subject.clone(),
                workspace.owner.clone(),
                workspace.owner_delegation.clone(),
                revoked_at,
            ),
            evidence(
                continuity_id.clone(),
                continuity_subject.clone(),
                workspace.owner.clone(),
                workspace.owner_delegation.clone(),
                revoked_at,
            ),
        ])
        .expect("trusted evidence identities are unique");
        let equal_time = HandoffReceipt::new(
            &workspace,
            &record,
            &generation,
            &handoff_grants,
            &equal_time_registry,
            &revocation_id,
            &BTreeSet::from([continuity_id.clone()]),
        );
        assert!(matches!(
            equal_time,
            Err(HandoffError::ContinuityPrecedesRevocation)
        ));

        let wrong_producer_registry = TrustedEvidenceRegistry::from_trusted_bootstrap([
            evidence(
                revocation_id.clone(),
                revocation_subject.clone(),
                workspace.owner.clone(),
                workspace.owner_delegation.clone(),
                revoked_at,
            ),
            evidence(
                continuity_id.clone(),
                continuity_subject.clone(),
                PrincipalId::new(),
                workspace.owner_delegation.clone(),
                continuity_at,
            ),
        ])
        .expect("trusted evidence identities are unique");
        assert!(matches!(
            HandoffReceipt::new(
                &workspace,
                &record,
                &generation,
                &handoff_grants,
                &wrong_producer_registry,
                &revocation_id,
                &BTreeSet::from([continuity_id.clone()]),
            ),
            Err(HandoffError::EvidenceProducerMismatch)
        ));

        let trusted_registry = TrustedEvidenceRegistry::from_trusted_bootstrap([
            evidence(
                revocation_id.clone(),
                revocation_subject,
                workspace.owner.clone(),
                workspace.owner_delegation.clone(),
                revoked_at,
            ),
            evidence(
                continuity_id.clone(),
                continuity_subject,
                workspace.owner.clone(),
                workspace.owner_delegation.clone(),
                continuity_at,
            ),
        ])
        .expect("trusted evidence identities are unique");
        let mut retroactive_grant = record.commissioner_grant().clone();
        retroactive_grant.revoked_at = Some(record.captured_at() - SignedDuration::from_secs(1));
        let retroactive = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            continuity_at,
            [retroactive_grant],
        )
        .expect("retroactive grant state is structurally representable for rejection");
        assert!(matches!(
            HandoffReceipt::new(
                &workspace,
                &record,
                &generation,
                &retroactive,
                &trusted_registry,
                &revocation_id,
                &BTreeSet::from([continuity_id.clone()]),
            ),
            Err(HandoffError::GrantStateMismatch)
        ));

        let stale_grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            revoked_at,
            [ended_grant.clone()],
        )
        .expect("stale grant snapshot is internally coherent");
        assert!(matches!(
            HandoffReceipt::new(
                &workspace,
                &record,
                &generation,
                &stale_grants,
                &trusted_registry,
                &revocation_id,
                &BTreeSet::from([continuity_id.clone()]),
            ),
            Err(HandoffError::GrantStateMismatch)
        ));

        let mut second_active = record.commissioner_grant().clone();
        second_active.delegation.id = DelegationId::new();
        second_active.delegation.subject = PrincipalId::new();
        second_active.revoked_at = None;
        let regranted = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            continuity_at,
            [ended_grant.clone(), second_active],
        )
        .expect("distinct grant identities form a coherent trusted snapshot");
        assert!(matches!(
            HandoffReceipt::new(
                &workspace,
                &record,
                &generation,
                &regranted,
                &trusted_registry,
                &revocation_id,
                &BTreeSet::from([continuity_id.clone()]),
            ),
            Err(HandoffError::CommissionerAuthorityStillActive)
        ));

        let mut ended_after_continuity = record.commissioner_grant().clone();
        ended_after_continuity.delegation.id = DelegationId::new();
        ended_after_continuity.delegation.subject = PrincipalId::new();
        ended_after_continuity.revoked_at = Some(continuity_at + SignedDuration::from_secs(1));
        let later_snapshot = continuity_at + SignedDuration::from_secs(2);
        let historically_active = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            later_snapshot,
            [ended_grant, ended_after_continuity],
        )
        .expect("later snapshot records both grants as ended");
        assert!(matches!(
            HandoffReceipt::new(
                &workspace,
                &record,
                &generation,
                &historically_active,
                &trusted_registry,
                &revocation_id,
                &BTreeSet::from([continuity_id.clone()]),
            ),
            Err(HandoffError::CommissionerAuthorityStillActive)
        ));

        let receipt = HandoffReceipt::new(
            &workspace,
            &record,
            &generation,
            &handoff_grants,
            &trusted_registry,
            &revocation_id,
            &BTreeSet::from([continuity_id]),
        )
        .expect("exact client custody and continuity produce a receipt");
        assert_eq!(
            &receipt.unresolved_obligations,
            record.unresolved_obligations(),
            "handoff must carry every known commissioning obligation forward"
        );
    }
}
