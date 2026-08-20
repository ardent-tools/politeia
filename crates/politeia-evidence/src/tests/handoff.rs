use std::collections::{BTreeMap, BTreeSet};

use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    DataClass, Delegation, Effect, ResourceBudget,
    commissioning::{
        ApprovedCommissioningSubject, CommissionerGrantRecord, TrustedCommissionerGrantRegistry,
        commissioning_approval_subject_digest, commissioning_institution_audience,
        commissioning_observation_set_digest, commissioning_observation_subject_digest,
        commissioning_workspace_resource, unresolved_obligations_digest,
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
    let trusted_grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [grant])
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
fn generation(workspace: &InstitutionWorkspace, record: &CommissioningRecord) -> RuntimeGeneration {
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

    let stale_grants =
        TrustedCommissionerGrantRegistry::from_trusted_bootstrap(revoked_at, [ended_grant.clone()])
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
