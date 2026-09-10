#![expect(
    clippy::expect_used,
    reason = "signed bootstrap fixtures must fail immediately when an invariant drifts"
)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::generation::{ApprovedGenerationInputs, ReproducibilityContract};
use politeia_core::institution::{InstitutionWorkspace, TrustDomainId};
use politeia_core::knowledge::{SourceCaptureRequest, TrustedSourceCaptureRegistry};
use politeia_core::lifecycle::{DeploymentTopology, LifecycleProfile};
use politeia_core::reconnaissance::{RECONNOITRE_ACTION, ReconnaissanceScope};
use politeia_core::trust::{
    AdmissionKind, Admitted, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey,
};
use politeia_core::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, InstitutionId,
    InstitutionWorkspaceId, OperationId, OperationSpec, PolicyBundleId, PrincipalId,
    ResourceBudget, SourceCaptureId,
};
use politeia_policy::bootstrap::{
    BOOTSTRAP_RECONNAISSANCE_BINDING, BootstrapReconnaissance, BootstrapRefusal,
    bootstrap_capture_resources, bootstrap_reconnaissance_operation,
    evaluate_bootstrap_reconnaissance,
};

struct Fixture {
    workspace: InstitutionWorkspace,
    commissioner: PrincipalId,
    alternate: PrincipalId,
    commissioner_key: SigningKey,
    alternate_key: SigningKey,
    anchors: InstitutionTrustAnchors,
    capture_id: SourceCaptureId,
    captures: TrustedSourceCaptureRegistry,
    delegation: Admitted<Delegation>,
    scope: ReconnaissanceScope,
    operation: OperationSpec,
    resources: BTreeSet<String>,
    intent: Digest,
    bootstrap: Digest,
    now: Timestamp,
}

impl Fixture {
    fn new() -> Self {
        let now: Timestamp = "2026-09-09T20:00:00Z"
            .parse()
            .expect("fixture timestamp is RFC 3339");
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let commissioner_key = SigningKey::from_bytes(&[22; 32]);
        let alternate_key = SigningKey::from_bytes(&[33; 32]);
        let owner = PrincipalId::new();
        let commissioner = PrincipalId::new();
        let alternate = PrincipalId::new();
        let workspace = workspace(owner.clone());
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            workspace.institution.clone(),
            workspace.id.clone(),
            [
                TrustedSigningKey::new(
                    owner.clone(),
                    owner_key.verifying_key().to_bytes(),
                    BTreeSet::from([AdmissionKind::Delegation]),
                )
                .expect("owner key is valid"),
                TrustedSigningKey::new(
                    commissioner.clone(),
                    commissioner_key.verifying_key().to_bytes(),
                    BTreeSet::from([AdmissionKind::Delegation, AdmissionKind::SourceCapture]),
                )
                .expect("commissioner key is valid"),
                TrustedSigningKey::new(
                    alternate.clone(),
                    alternate_key.verifying_key().to_bytes(),
                    BTreeSet::from([AdmissionKind::SourceCapture]),
                )
                .expect("alternate key is valid"),
            ],
        )
        .expect("fixture principals are unique");
        let capture_id = SourceCaptureId::new();
        let adapter = AdapterId::new();
        let delegation_id = DelegationId::new();
        let capture_request = SourceCaptureRequest {
            id: capture_id.clone(),
            source: "institution-crm".to_string(),
            adapter: adapter.clone(),
            subject: Digest::blake3(b"account portfolio"),
            statement: Digest::blake3(b"expected source snapshot"),
            observed_at: now,
            reconnaissance_delegation: delegation_id.clone(),
            manifest: BTreeSet::from([
                "accounts.json".to_string(),
                "schema/accounts.json".to_string(),
            ]),
            descriptor_digest: Digest::blake3(b"bounded capture descriptor"),
            content_manifest_digest: Digest::blake3(b"expected selected bytes"),
        };
        let resources = bootstrap_capture_resources(&capture_request);
        let delegation_payload = Delegation {
            id: delegation_id.clone(),
            issuer: owner.clone(),
            subject: commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([RECONNOITRE_ACTION.to_string()]),
            resources: resources.clone(),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from([format!("institution:{}", workspace.institution.0)]),
            expires_at: now + SignedDuration::from_hours(2),
            budget: finite_budget(),
        };
        let delegation =
            admit_delegation(&anchors, &workspace, &owner, &owner_key, delegation_payload);
        let captures = admit_capture(
            &anchors,
            &workspace,
            &commissioner,
            &commissioner_key,
            capture_request,
        );
        Self {
            workspace,
            commissioner: commissioner.clone(),
            alternate,
            commissioner_key,
            alternate_key,
            anchors,
            capture_id,
            captures,
            delegation,
            scope: ReconnaissanceScope {
                commissioner,
                delegation: delegation_id,
                sources: BTreeSet::from(["institution-crm".to_string()]),
                adapters: BTreeSet::from([adapter]),
                expires_at: now + SignedDuration::from_hours(1),
            },
            operation: bootstrap_reconnaissance_operation(
                OperationId::new(),
                BTreeSet::from([DataClass::Internal]),
            ),
            resources,
            intent: Digest::blake3(b"canonical operation intent"),
            bootstrap: Digest::blake3(b"owner-signed bootstrap record"),
            now,
        }
    }

    fn evaluate(&self) -> Result<politeia_policy::PolicyDecision, BootstrapRefusal> {
        evaluate_bootstrap_reconnaissance(&BootstrapReconnaissance {
            workspace: &self.workspace,
            captures: &self.captures,
            capture: &self.capture_id,
            delegation: &self.delegation,
            scope: &self.scope,
            principal: &self.commissioner,
            operation: &self.operation,
            resources: &self.resources,
            intent_digest: &self.intent,
            bootstrap_record_digest: &self.bootstrap,
            at: self.now,
        })
    }

    fn capture_request(&self) -> SourceCaptureRequest {
        self.captures
            .resolve(&self.capture_id)
            .expect("fixture capture is admitted")
            .request()
            .clone()
    }
}

#[test]
fn admits_only_the_exact_signed_read_and_preserves_no_control_claim() {
    let fixture = Fixture::new();
    let decision = fixture
        .evaluate()
        .expect("exact bootstrap read is admitted");

    assert!(decision.allowed);
    assert_eq!(decision.bundle, fixture.workspace.policy_bundle);
    assert_eq!(decision.policy_digest, fixture.workspace.policy_digest);
    assert_eq!(decision.intent_digest, fixture.intent);
    assert_eq!(decision.principal, fixture.commissioner);
    assert_eq!(decision.binding_ids, [BOOTSTRAP_RECONNAISSANCE_BINDING]);
    assert!(decision.control_runs.is_empty());
    assert!(decision.activation_proofs.is_empty());
    assert!(decision.waiver_ids.is_empty());
}

#[test]
fn refuses_a_capture_registry_from_another_installed_workspace() {
    let mut fixture = Fixture::new();
    let foreign = InstitutionTrustAnchors::from_trusted_bootstrap(
        fixture.workspace.institution.clone(),
        InstitutionWorkspaceId::new(),
        [TrustedSigningKey::new(
            fixture.commissioner.clone(),
            fixture.commissioner_key.verifying_key().to_bytes(),
            BTreeSet::from([AdmissionKind::SourceCapture]),
        )
        .expect("commissioner key is valid")],
    )
    .expect("foreign anchors are valid");
    fixture.captures = TrustedSourceCaptureRegistry::admit_signed(&foreign, [])
        .expect("an empty registry retains installed scope");

    assert!(matches!(
        fixture.evaluate(),
        Err(BootstrapRefusal::ForeignCaptureWorkspace)
    ));
}

#[test]
fn refuses_a_signed_grant_that_did_not_come_from_the_installed_owner() {
    let mut fixture = Fixture::new();
    let mut delegation = fixture.delegation.payload().clone();
    delegation.issuer = fixture.commissioner.clone();
    fixture.delegation = admit_delegation(
        &fixture.anchors,
        &fixture.workspace,
        &fixture.commissioner,
        &fixture.commissioner_key,
        delegation,
    );

    assert!(matches!(
        fixture.evaluate(),
        Err(BootstrapRefusal::DelegationIssuerNotOwner)
    ));
}

#[test]
fn refuses_a_capture_signed_by_someone_other_than_the_authority_holder() {
    let mut fixture = Fixture::new();
    fixture.captures = admit_capture(
        &fixture.anchors,
        &fixture.workspace,
        &fixture.alternate,
        &fixture.alternate_key,
        fixture.capture_request(),
    );

    assert!(matches!(
        fixture.evaluate(),
        Err(BootstrapRefusal::PrincipalMismatch)
    ));
}

#[test]
fn refuses_broader_scope_or_any_resource_substitution() {
    let mut broad_scope = Fixture::new();
    broad_scope
        .scope
        .sources
        .insert("another-source".to_string());
    assert!(matches!(
        broad_scope.evaluate(),
        Err(BootstrapRefusal::SourceScopeMismatch)
    ));

    let mut missing_descriptor = Fixture::new();
    missing_descriptor.resources.remove(&format!(
        "capture-descriptor:{}",
        missing_descriptor
            .capture_request()
            .descriptor_digest
            .as_str()
    ));
    assert!(matches!(
        missing_descriptor.evaluate(),
        Err(BootstrapRefusal::IntentResourceMismatch)
    ));
}

#[test]
fn refuses_productive_retrying_or_evidence_free_operation_shapes() {
    let mut productive = Fixture::new();
    productive
        .operation
        .effects
        .insert(Effect::WriteExternalSystem);
    assert!(matches!(
        productive.evaluate(),
        Err(BootstrapRefusal::OperationEffectMismatch)
    ));

    let mut retrying = Fixture::new();
    retrying.operation.retryable = true;
    assert!(matches!(
        retrying.evaluate(),
        Err(BootstrapRefusal::OperationRetryMismatch)
    ));

    let mut evidence_free = Fixture::new();
    evidence_free.operation.evidence_obligations.clear();
    assert!(matches!(
        evidence_free.evaluate(),
        Err(BootstrapRefusal::OperationEvidenceMismatch)
    ));
}

#[test]
fn refuses_expired_authority_and_capture_times_outside_the_scope() {
    let mut expired = Fixture::new();
    expired.now += SignedDuration::from_hours(1);
    assert!(matches!(
        expired.evaluate(),
        Err(BootstrapRefusal::ReconnaissanceAuthority(_))
    ));

    let mut late_capture = Fixture::new();
    let mut capture = late_capture.capture_request();
    capture.observed_at = late_capture.scope.expires_at;
    late_capture.captures = admit_capture(
        &late_capture.anchors,
        &late_capture.workspace,
        &late_capture.commissioner,
        &late_capture.commissioner_key,
        capture,
    );
    assert!(matches!(
        late_capture.evaluate(),
        Err(BootstrapRefusal::CaptureAfterExpiry)
    ));
}

#[test]
fn subject_binding_changes_with_intent_or_bootstrap_record() {
    let mut fixture = Fixture::new();
    let baseline_subject = fixture.evaluate().expect("baseline is admitted").subject;

    let original_intent = fixture.intent.clone();
    fixture.intent = Digest::blake3(b"another canonical intent");
    assert_ne!(
        fixture
            .evaluate()
            .expect("changed intent remains well-scoped")
            .subject,
        baseline_subject
    );

    fixture.intent = original_intent;
    fixture.bootstrap = Digest::blake3(b"another signed bootstrap record");
    assert_ne!(
        fixture
            .evaluate()
            .expect("changed bootstrap remains well-scoped")
            .subject,
        baseline_subject
    );
}

fn workspace(owner: PrincipalId) -> InstitutionWorkspace {
    InstitutionWorkspace {
        id: InstitutionWorkspaceId::new(),
        institution: InstitutionId::new(),
        trust_domain: "fixture:bootstrap"
            .parse::<TrustDomainId>()
            .expect("fixture trust domain is canonical"),
        owner,
        owner_delegation: DelegationId::new(),
        approved_model_digest: Digest::blake3(b"model"),
        policy_bundle: PolicyBundleId::new(),
        policy_digest: Digest::blake3(b"installed policy"),
        approved_generation: ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Bootstrap,
            topology: DeploymentTopology::LocalDevelopment,
            schema_digests: BTreeMap::new(),
            adapter_digests: BTreeMap::new(),
            pack_digests: BTreeMap::new(),
            component_digests: BTreeMap::new(),
            excluded_commissioning_capabilities: BTreeSet::new(),
            specializer_digest: Digest::blake3(b"specializer"),
            toolchain_digest: Digest::blake3(b"toolchain"),
            reproducibility: ReproducibilityContract::Deterministic,
        },
        secret_references: BTreeSet::new(),
    }
}

fn finite_budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(1_000),
        cpu_ms: Some(100),
        memory_bytes: Some(1_048_576),
        io_bytes: Some(1_048_576),
        network_bytes: Some(1_048_576),
        external_cost_microunits: Some(0),
    }
}

fn admit_delegation(
    anchors: &InstitutionTrustAnchors,
    workspace: &InstitutionWorkspace,
    signer: &PrincipalId,
    key: &SigningKey,
    delegation: Delegation,
) -> Admitted<Delegation> {
    let wire = SignedAdmissionWire::sign(
        AdmissionKind::Delegation,
        workspace.institution.clone(),
        workspace.id.clone(),
        signer.clone(),
        delegation,
        key,
    )
    .expect("fixture delegation signs");
    anchors
        .admit_expected(AdmissionKind::Delegation, wire)
        .expect("fixture delegation is admitted")
}

fn admit_capture(
    anchors: &InstitutionTrustAnchors,
    workspace: &InstitutionWorkspace,
    signer: &PrincipalId,
    key: &SigningKey,
    capture: SourceCaptureRequest,
) -> TrustedSourceCaptureRegistry {
    let wire = SignedAdmissionWire::sign(
        AdmissionKind::SourceCapture,
        workspace.institution.clone(),
        workspace.id.clone(),
        signer.clone(),
        capture,
        key,
    )
    .expect("fixture capture signs");
    TrustedSourceCaptureRegistry::admit_signed(anchors, [wire])
        .expect("fixture capture is admitted")
}
