//! Fixtures shared by the crate's test modules.
//!
//! WHY one module rather than a copy per test file: a runtime generation takes
//! a workspace, a commissioning record, a grant registry and an evidence
//! registry to build, and a second copy of that chain is a second thing to keep
//! in step with the validation it is built to satisfy. When they drift, the
//! copy that drifted still passes its own tests.

use std::collections::{BTreeMap, BTreeSet};

use jiff::{SignedDuration, Timestamp};

use crate::commissioning::{
    ApprovedCommissioningSubject, CommissionerGrantRecord, CommissioningRecord,
    TrustedCommissionerGrantRegistry, commissioning_approval_subject_digest,
    commissioning_institution_audience, commissioning_observation_set_digest,
    commissioning_observation_subject_digest, commissioning_workspace_resource,
    unresolved_obligations_digest,
};
use crate::evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry};
use crate::generation::{
    ApprovedGenerationInputs, CommissioningCapability, ReproducibilityContract,
    RuntimeGenerationInputs,
};
use crate::institution::{InstitutionWorkspace, TrustDomainId};
use crate::lifecycle::{DeploymentTopology, LifecycleProfile};
use crate::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId, ResourceBudget,
};

pub(crate) struct Fixture {
    pub(crate) inputs: RuntimeGenerationInputs,
    pub(crate) workspace: InstitutionWorkspace,
    pub(crate) commissioning: CommissioningRecord,
}

/// A fixture whose generation is reproducible bit-for-bit.
pub(crate) fn fixture() -> Fixture {
    fixture_with(ReproducibilityContract::Deterministic)
}

/// A fixture built around an exact reproducibility posture.
///
/// WHY the contract is a parameter rather than something a caller edits
/// afterwards: it is bound in three places -- the approved plan, the workspace
/// manifest that approves it, and the commissioning approval over that plan's
/// digest. Changing one leaves the other two describing a different plan, and
/// `RuntimeGeneration::derive` rejects the pair on provenance. That refusal is
/// `docs/02-CONSTITUTION.md`'s exact-binding law working; building the chain
/// around the contract is how a test asks a different question without
/// defeating it.
#[expect(
    clippy::expect_used,
    reason = "canonical trust-domain fixture must fail loudly if validation drifts"
)]
pub(crate) fn fixture_with(reproducibility: ReproducibilityContract) -> Fixture {
    let institution = InstitutionId::new();
    let workspace_id = InstitutionWorkspaceId::new();
    let trust_domain: TrustDomainId = "client-a:production"
        .parse()
        .expect("fixture trust domain is canonical");
    let policy_bundle = PolicyBundleId::new();
    let policy_digest = Digest::blake3(b"policy");
    let component_digests =
        BTreeMap::from([("politeiad".to_string(), Digest::blake3(b"executable"))]);
    let approved_generation = ApprovedGenerationInputs {
        source_digest: Digest::blake3(b"source"),
        lifecycle: LifecycleProfile::Operational,
        topology: DeploymentTopology::ClientControlledSingleTenant,
        schema_digests: BTreeMap::from([("operation".to_string(), Digest::blake3(b"schema"))]),
        adapter_digests: BTreeMap::from([(AdapterId::new(), Digest::blake3(b"adapter"))]),
        pack_digests: BTreeMap::new(),
        component_digests,
        excluded_commissioning_capabilities: CommissioningCapability::all(),
        specializer_digest: Digest::blake3(b"specializer"),
        toolchain_digest: Digest::blake3(b"toolchain"),
        reproducibility,
    };
    let workspace = InstitutionWorkspace {
        id: workspace_id.clone(),
        institution: institution.clone(),
        trust_domain: trust_domain.clone(),
        owner: PrincipalId::new(),
        owner_delegation: DelegationId::new(),
        approved_model_digest: Digest::blake3(b"model"),
        policy_bundle: policy_bundle.clone(),
        policy_digest: policy_digest.clone(),
        approved_generation: approved_generation.clone(),
        secret_references: BTreeSet::new(),
    };
    let workspace_digest = workspace.digest().expect("fixture workspace encodes");
    let as_of = Timestamp::now();
    let commissioner = PrincipalId::new();
    let commissioner_delegation = Delegation {
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
        delegation: commissioner_delegation.clone(),
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
        producer_delegation: commissioner_delegation.id.clone(),
        method: "bounded read-only discovery".to_string(),
        payload_digest: Digest::blake3(b"observation payload"),
        observed_at: as_of - SignedDuration::from_secs(30),
        independence: IndependenceClass::SelfReported,
    };
    let observation_set_digest =
        commissioning_observation_set_digest(std::slice::from_ref(&observation))
            .expect("fixture observation set encodes");
    let obligations = BTreeSet::new();
    let approved_subjects = [
        ApprovedCommissioningSubject::InstitutionalModel {
            digest: workspace.approved_model_digest.clone(),
        },
        ApprovedCommissioningSubject::PolicyBundle {
            id: workspace.policy_bundle.clone(),
            digest: workspace.policy_digest.clone(),
        },
        ApprovedCommissioningSubject::GenerationInputs {
            digest: approved_generation
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
    let approvals: Vec<_> = approved_subjects
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
    let approval_ids = approvals.iter().map(|record| record.id.clone()).collect();
    let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap(
        std::iter::once(observation).chain(approvals),
    )
    .expect("fixture evidence identities are unique");
    let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [grant])
        .expect("fixture grant is unique and active");
    let commissioning = CommissioningRecord::new(
        &workspace,
        &grants,
        &evidence,
        &observation_ids,
        &approval_ids,
        obligations,
    )
    .expect("fixture commissioning record is complete");
    let commissioning_record_digest = commissioning
        .digest()
        .expect("fixture commissioning record encodes");
    let inputs = RuntimeGenerationInputs {
        institution: institution.clone(),
        workspace: workspace_id.clone(),
        workspace_digest: workspace_digest.clone(),
        trust_domain,
        policy_bundle: policy_bundle.clone(),
        policy_digest: policy_digest.clone(),
        commissioning_record: commissioning.id().clone(),
        commissioning_record_digest: commissioning_record_digest.clone(),
        approved: approved_generation,
    };
    Fixture {
        inputs,
        workspace,
        commissioning,
    }
}
