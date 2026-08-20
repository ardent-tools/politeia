//! Commissioning authority, approval, and provenance tests.

use jiff::SignedDuration;

use super::*;
use crate::{
    AdapterId, DataClass, Effect, ResourceBudget,
    generation::{CommissioningCapability, ReproducibilityContract},
    institution::TrustDomainId,
    lifecycle::{DeploymentTopology, LifecycleProfile},
};

struct Fixture {
    workspace: InstitutionWorkspace,
    as_of: Timestamp,
    grant: CommissionerGrantRecord,
    observation: EvidenceRecord,
    approvals: Vec<EvidenceRecord>,
    obligations: BTreeSet<String>,
}

#[expect(
    clippy::expect_used,
    reason = "canonical trust-domain fixture must fail loudly if validation drifts"
)]
fn workspace() -> InstitutionWorkspace {
    InstitutionWorkspace {
        id: InstitutionWorkspaceId::new(),
        institution: InstitutionId::new(),
        trust_domain: "client-a:commissioning"
            .parse::<TrustDomainId>()
            .expect("fixture trust domain is canonical"),
        owner: PrincipalId::new(),
        owner_delegation: DelegationId::new(),
        approved_model_digest: Digest::blake3(b"approved model"),
        policy_bundle: PolicyBundleId::new(),
        policy_digest: Digest::blake3(b"approved policy"),
        approved_generation: ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Operational,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::from([("operation".to_string(), Digest::blake3(b"schema"))]),
            adapter_digests: BTreeMap::from([(AdapterId::new(), Digest::blake3(b"adapter"))]),
            pack_digests: BTreeMap::new(),
            component_digests: BTreeMap::new(),
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
        },
        secret_references: BTreeSet::new(),
    }
}

fn grant(workspace: &InstitutionWorkspace, as_of: Timestamp) -> CommissionerGrantRecord {
    CommissionerGrantRecord {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        valid_from: as_of - SignedDuration::from_mins(5),
        revoked_at: None,
        delegation: Delegation {
            id: DelegationId::new(),
            issuer: workspace.owner.clone(),
            subject: PrincipalId::new(),
            parent: Some(workspace.owner_delegation.clone()),
            actions: BTreeSet::from([COMMISSION_ACTION.to_string()]),
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
        },
    }
}

#[expect(
    clippy::expect_used,
    reason = "commissioning evidence fixtures must encode their exact grant subject"
)]
fn observation(
    workspace: &InstitutionWorkspace,
    grant: &CommissionerGrantRecord,
    as_of: Timestamp,
) -> EvidenceRecord {
    let payload_digest = Digest::blake3(b"bounded observation");
    EvidenceRecord {
        id: EvidenceId::new(),
        subject: commissioning_observation_subject_digest(
            &workspace.institution,
            &workspace.id,
            &grant.digest().expect("fixture grant encodes"),
            &payload_digest,
        )
        .expect("fixture observation subject encodes"),
        producer: grant.delegation.subject.clone(),
        producer_delegation: grant.delegation.id.clone(),
        method: "bounded read-only discovery".to_string(),
        payload_digest,
        observed_at: as_of - SignedDuration::from_mins(2),
        independence: IndependenceClass::SelfReported,
    }
}

#[expect(
    clippy::expect_used,
    reason = "approval fixtures bind exact typed subjects to admitted observations"
)]
fn approvals(
    workspace: &InstitutionWorkspace,
    observation: &EvidenceRecord,
    obligations: &BTreeSet<String>,
    as_of: Timestamp,
) -> Vec<EvidenceRecord> {
    let observation_set_digest =
        commissioning_observation_set_digest(std::slice::from_ref(observation))
            .expect("fixture observation set encodes");
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
                .expect("fixture generation inputs encode"),
        },
        ApprovedCommissioningSubject::UnresolvedObligations {
            digest: unresolved_obligations_digest(
                &workspace.institution,
                &workspace.id,
                obligations,
            )
            .expect("fixture obligations encode"),
        },
    ];
    subjects
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
            observed_at: as_of - SignedDuration::from_mins(1),
            independence: IndependenceClass::HumanAuthority,
        })
        .collect()
}

fn fixture(obligations: BTreeSet<String>) -> Fixture {
    let workspace = workspace();
    let as_of = Timestamp::now();
    let grant = grant(&workspace, as_of);
    let observation = observation(&workspace, &grant, as_of);
    let approvals = approvals(&workspace, &observation, &obligations, as_of);
    Fixture {
        workspace,
        as_of,
        grant,
        observation,
        approvals,
        obligations,
    }
}

#[expect(
    clippy::expect_used,
    reason = "trusted fixture registries must reject accidental duplicate identities"
)]
fn record(
    fixture: &Fixture,
    grants: impl IntoIterator<Item = CommissionerGrantRecord>,
    evidence: impl IntoIterator<Item = EvidenceRecord>,
    obligations: BTreeSet<String>,
) -> Result<CommissioningRecord, CommissioningError> {
    let grant_registry =
        TrustedCommissionerGrantRegistry::from_trusted_bootstrap(fixture.as_of, grants)
            .expect("fixture grant registry is coherent");
    let evidence: Vec<_> = evidence.into_iter().collect();
    let observation_ids = BTreeSet::from([fixture.observation.id.clone()]);
    let approval_ids = fixture
        .approvals
        .iter()
        .map(|approval| approval.id.clone())
        .collect();
    let evidence_registry = TrustedEvidenceRegistry::from_trusted_bootstrap(evidence)
        .expect("fixture evidence identities are unique");
    CommissioningRecord::new(
        &fixture.workspace,
        &grant_registry,
        &evidence_registry,
        &observation_ids,
        &approval_ids,
        obligations,
    )
}

fn fixture_evidence(fixture: &Fixture) -> Vec<EvidenceRecord> {
    std::iter::once(fixture.observation.clone())
        .chain(fixture.approvals.clone())
        .collect()
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "valid commissioning fixture must prove exact trusted resolution"
)]
fn record_resolves_full_grant_evidence_and_obligations() {
    let fixture = fixture(BTreeSet::from(["retain legacy audit log".to_string()]));
    let record = record(
        &fixture,
        [fixture.grant.clone()],
        fixture_evidence(&fixture),
        fixture.obligations.clone(),
    )
    .expect("exact trusted commissioning inputs must validate");
    assert_eq!(record.commissioner(), &fixture.grant.delegation.subject);
    assert_eq!(
        record.commissioner_delegation(),
        &fixture.grant.delegation.id
    );
    assert_eq!(record.unresolved_obligations(), &fixture.obligations);
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "rebound evidence fixture must preserve an exact grant identity"
)]
fn unadmitted_or_rebound_observations_are_rejected() {
    let fixture = fixture(BTreeSet::new());
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            fixture.approvals.clone(),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceNotAdmitted)
    ));

    let mut rebound = fixture.observation.clone();
    rebound.payload_digest = Digest::blake3(b"rebound payload");
    rebound.subject = commissioning_observation_subject_digest(
        &fixture.workspace.institution,
        &fixture.workspace.id,
        &fixture.grant.digest().expect("fixture grant encodes"),
        &rebound.payload_digest,
    )
    .expect("rebound observation subject encodes");
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            std::iter::once(rebound).chain(fixture.approvals.clone()),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::UnexpectedApproval)
    ));
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "observation-set identity must be invariant to caller iteration order"
)]
fn observation_set_digest_has_canonical_record_order() {
    let fixture = fixture(BTreeSet::new());
    let first = fixture.observation;
    let mut second = first.clone();
    second.id = EvidenceId::new();
    second.payload_digest = Digest::blake3(b"second observation payload");

    let forward = commissioning_observation_set_digest(&[first.clone(), second.clone()])
        .expect("forward observation set encodes");
    let reverse = commissioning_observation_set_digest(&[second, first])
        .expect("reverse observation set encodes");
    assert_eq!(
        forward, reverse,
        "set identity cannot depend on slice order"
    );
}

#[test]
fn grant_authority_and_singular_active_set_fail_closed() {
    let fixture = fixture(BTreeSet::new());
    let mut mislabeled = fixture.grant.clone();
    mislabeled.workspace = InstitutionWorkspaceId::new();
    assert!(matches!(
        TrustedCommissionerGrantRegistry::from_trusted_bootstrap(fixture.as_of, [mislabeled]),
        Err(CommissionerGrantRegistryError::ScopeMismatch)
    ));

    let mut second = fixture.grant.clone();
    second.delegation.id = DelegationId::new();
    second.delegation.subject = PrincipalId::new();
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone(), second],
            fixture_evidence(&fixture),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::AmbiguousActiveGrant)
    ));

    let mut wrong_issuer = fixture.grant.clone();
    wrong_issuer.delegation.issuer = PrincipalId::new();
    assert!(matches!(
        record(
            &fixture,
            [wrong_issuer],
            fixture_evidence(&fixture),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::GrantAuthorityMismatch)
    ));
}

#[test]
fn observation_axes_and_time_are_exact() {
    let fixture = fixture(BTreeSet::new());
    let mut wrong_producer = fixture.observation.clone();
    wrong_producer.producer = PrincipalId::new();
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            std::iter::once(wrong_producer).chain(fixture.approvals.clone()),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceProducerMismatch)
    ));

    let mut expired = fixture.observation.clone();
    expired.observed_at = fixture.grant.delegation.expires_at;
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            std::iter::once(expired).chain(fixture.approvals.clone()),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceOutsideWindow)
    ));
}

#[test]
fn owner_approval_axes_and_class_are_exact() {
    let fixture = fixture(BTreeSet::new());
    let mut wrong_owner = fixture.approvals.clone();
    wrong_owner[0].producer = PrincipalId::new();
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            std::iter::once(fixture.observation.clone()).chain(wrong_owner),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceProducerMismatch)
    ));

    let mut self_reported = fixture.approvals.clone();
    self_reported[0].independence = IndependenceClass::SelfReported;
    assert!(matches!(
        record(
            &fixture,
            [fixture.grant.clone()],
            std::iter::once(fixture.observation.clone()).chain(self_reported),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceClassMismatch)
    ));
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "explicit empty-obligation approval must remain constructible"
)]
fn obligations_cannot_change_or_disappear_after_approval() {
    let populated = fixture(BTreeSet::from(["retain audit log".to_string()]));
    assert!(matches!(
        record(
            &populated,
            [populated.grant.clone()],
            fixture_evidence(&populated),
            BTreeSet::new(),
        ),
        Err(CommissioningError::UnexpectedApproval)
    ));

    let empty = fixture(BTreeSet::new());
    record(
        &empty,
        [empty.grant.clone()],
        fixture_evidence(&empty),
        BTreeSet::new(),
    )
    .expect("empty obligations require and accept their exact explicit approval");
}

#[test]
fn altered_grant_scope_invalidates_existing_observations() {
    let fixture = fixture(BTreeSet::new());
    let mut changed = fixture.grant.clone();
    changed
        .delegation
        .effects
        .insert(Effect::WriteExternalSystem);
    assert!(matches!(
        record(
            &fixture,
            [changed],
            fixture_evidence(&fixture),
            fixture.obligations.clone(),
        ),
        Err(CommissioningError::EvidenceSubjectMismatch)
    ));
}
