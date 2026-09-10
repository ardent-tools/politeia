//! Public, process-bound operational material for the package acceptance flow.
//!
//! The builders in this module create signed transport documents and exact
//! artifact bytes. They do not construct a service, dispatcher, or storage
//! handle; callers must admit every returned request through the daemon CLI.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    CapabilityProfileId, CapabilityVerificationId, DataClass, Delegation, DelegationId, Digest,
    Effect, EvidenceId, ExecutionLocality, ExecutionResourceId, OperationId, OperationSpec,
    PrincipalId, ResourceBudget, RoutingDecisionId,
    canonical::to_canonical_bytes,
    evidence::{EvidenceRequest, IndependenceClass},
    institution::TrustDomainId,
    reconnaissance::RECONNOITRE_ACTION,
    trust::{AdmissionKind, SignedAdmissionWire, WorkspaceBootstrapRequest},
};
use politeia_evidence::{
    assurance::{
        ActivationProof, RUN_POLICY_CONTROL_ACTION, VERIFY_POLICY_CONTROL_ACTION,
        policy_control_resource,
    },
    authority::institution_audience,
};
use politeia_policy::{
    Consequence, DetectorSpec, EvidenceClass, PolicyBinding,
    hardening::{BindingAuthority, HardeningLadder, HardeningState},
    operational::{
        OperationalDetector, OperationalEvaluationRequest, OperationalPolicyRegistry,
        PublicDetectorRule, operation_scope,
    },
};
use politeia_runtime::{
    OperationIntent,
    routing::{
        AvailabilitySnapshot, CapabilityProfile, CapabilityVerificationRecord,
        ExecutionRequirement, ExecutionResource, ExecutionResourceDescriptor, Router,
        RoutingRejection, SoftPreference,
    },
};
use politeiad::{
    learning::{COMPILE_CONTEXT_ACTION, CONTEXT_READ_EFFECT, DISCOVER_CAPABILITIES_ACTION},
    service_operation::{
        BOUNDED_LOCAL_OPERATION_CAPABILITY, BOUNDED_LOCAL_OPERATION_TASK_CLASS,
        CAPABILITY_QUALIFICATION_METHOD, CAPTURE_SOURCE_OPERATION, COMPILE_CONTEXT_OPERATION,
        CapabilityEvidenceSubmission, CapabilityQualificationEvidence,
        CapabilityVerificationEvidence, DETECTOR_CALIBRATION_METHOD,
        DISCOVER_CAPABILITIES_OPERATION, DetectorCalibrationEvidenceSubmission,
        InstalledOperationHandler, OPERATION_RECEIPT_OBLIGATION, OperationSubmission,
        OperationalControlEvidence, OperationalExecutionRegistry, RESOURCE_MANIFEST_ACTION,
        RESOURCE_MANIFEST_OPERATION, RegisteredOperation, VERIFY_EXECUTION_CAPABILITY_ACTION,
        capability_verification_resource,
    },
};

use super::ReferenceFixture;

/// Public detector identity used by every operational policy binding.
pub(crate) const PUBLIC_RESOURCE_DETECTOR: &str = "public-resource-boundary";
/// Stable forbidden input used to demonstrate an actual policy denial.
pub(crate) const PLANTED_FORBIDDEN_RESOURCE: &str = "forbidden:planted-operation";
/// Exact normalized denial reason emitted by the enforced binding.
pub(crate) const PLANTED_DENIAL_REASON: &str = "public-resource-boundary violation applies Deny";

/// Signed daemon admission and operation request for one manifest canary.
pub(crate) struct PreparedManifestOperation {
    /// Owner-signed request to admit the exact operation grant first.
    pub(crate) authority_admission: serde_json::Value,
    /// JSON supplied only through `politeia operate` after grant admission.
    pub(crate) operate: serde_json::Value,
}

/// Canonical operational artifacts plus all independently signed evidence.
pub(crate) struct OperationalFixture {
    policy: OperationalPolicyRegistry,
    execution: OperationalExecutionRegistry,
    detector_rule: PublicDetectorRule,
    capability_evidence: Vec<CapabilityVerificationEvidence>,
    capability_admissions: Vec<serde_json::Value>,
    run_authority: SignedAdmissionWire<Delegation>,
    activation_authority: SignedAdmissionWire<Delegation>,
    activation: SignedAdmissionWire<ActivationProof>,
}

impl OperationalFixture {
    /// Replace placeholder policy/registry files with canonical typed artifacts
    /// and bind the owner-signed workspace skeleton to their exact digests.
    #[expect(
        clippy::expect_used,
        reason = "the process fixture must fail loudly when typed artifacts drift"
    )]
    pub(crate) fn install(fixture: &mut ReferenceFixture) -> Self {
        let workspace = fixture.host_trust.workspace.clone();
        let executable = fixture.generation_material.join("components/executable");
        let executable_digest =
            Digest::blake3(&fs::read(&executable).expect("staged package executable is readable"));
        let adapter = fixture.adapter.clone();

        let local_resource = ExecutionResource {
            id: ExecutionResourceId::new(),
            descriptor: ExecutionResourceDescriptor::DeterministicTool {
                artifact_digest: executable_digest,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            adapter: adapter.clone(),
            trust_domain: workspace.trust_domain.clone(),
            control_domain: trust_domain("reference.local-executor"),
            locality: ExecutionLocality::ClientLocal,
            allowed_data_classes: BTreeSet::from([DataClass::Public, DataClass::Internal]),
            allowed_effects: BTreeSet::from([
                Effect::CreateArtifact,
                Effect::ReadExternalSystem,
                Effect::ReadInstitutionalContext,
            ]),
            max_context_tokens: 32_768,
            estimated_cost_microunits: 1_000,
            estimated_latency_ms: 50,
        };
        let remote_resource = ExecutionResource {
            id: ExecutionResourceId::new(),
            descriptor: ExecutionResourceDescriptor::Model {
                provider: "reference-remote-provider".to_string(),
                model: "cheap-unapproved-model".to_string(),
                runtime: "reference-remote-runtime".to_string(),
                harness: "reference-remote-harness".to_string(),
            },
            adapter,
            trust_domain: trust_domain("reference.remote-provider"),
            control_domain: trust_domain("reference.remote-provider-control"),
            locality: ExecutionLocality::ProviderRemote,
            allowed_data_classes: BTreeSet::from([DataClass::Public, DataClass::Internal]),
            allowed_effects: BTreeSet::from([
                Effect::CreateArtifact,
                Effect::ReadExternalSystem,
                Effect::ReadInstitutionalContext,
            ]),
            max_context_tokens: 1_000_000,
            estimated_cost_microunits: 1,
            estimated_latency_ms: 1,
        };
        let operations = registered_operations(&workspace.trust_domain);
        let local_evidence = EvidenceId::new();
        let remote_evidence = EvidenceId::new();
        let verifier_domain = trust_domain("reference.independent-verifier");
        let local_profile_id = CapabilityProfileId::new();
        let remote_profile_id = CapabilityProfileId::new();
        let local_probe_started_at = Timestamp::now();
        let local_verification = CapabilityVerificationRecord {
            id: CapabilityVerificationId::new(),
            profile: local_profile_id.clone(),
            resource: local_resource.id.clone(),
            resource_digest: local_resource.digest().expect("local resource digests"),
            task_classes: BTreeSet::from([BOUNDED_LOCAL_OPERATION_TASK_CLASS.to_string()]),
            capabilities: BTreeSet::from([BOUNDED_LOCAL_OPERATION_CAPABILITY.to_string()]),
            verifier: fixture.identities.verifier.clone(),
            verifier_control_domain: verifier_domain.clone(),
            evidence: BTreeSet::from([local_evidence.clone()]),
            observed_at: local_probe_started_at,
            expires_at: local_probe_started_at + SignedDuration::from_hours(2),
        };
        let remote_probe_started_at = Timestamp::now();
        let remote_verification = CapabilityVerificationRecord {
            id: CapabilityVerificationId::new(),
            profile: remote_profile_id.clone(),
            resource: remote_resource.id.clone(),
            resource_digest: remote_resource.digest().expect("remote resource digests"),
            task_classes: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            verifier: fixture.identities.verifier.clone(),
            verifier_control_domain: verifier_domain,
            evidence: BTreeSet::from([remote_evidence.clone()]),
            observed_at: remote_probe_started_at,
            expires_at: remote_probe_started_at + SignedDuration::from_hours(2),
        };
        let manifest_operation = operations
            .iter()
            .find(|operation| operation.spec.name == RESOURCE_MANIFEST_OPERATION)
            .expect("manifest operation is registered");
        let (local_verification, local_profile, local_qualification, local_evidence_observed_at) =
            qualified_capability_material(
                local_verification,
                &local_resource,
                Some(manifest_operation),
            );
        let (
            remote_verification,
            remote_profile,
            remote_qualification,
            remote_evidence_observed_at,
        ) = qualified_capability_material(remote_verification, &remote_resource, None);
        let execution = OperationalExecutionRegistry::new(
            operations,
            vec![local_resource, remote_resource],
            vec![local_profile, remote_profile],
            vec![local_verification.clone(), remote_verification.clone()],
            BTreeSet::from([
                local_verification.resource.clone(),
                remote_verification.resource.clone(),
            ]),
        )
        .expect("typed execution registry is coherent");

        let scopes: BTreeSet<_> = execution
            .capability_inventory()
            .operations
            .iter()
            .map(|operation| operation_scope(&operation.spec))
            .collect();
        let detector_rule = PublicDetectorRule::ResourcePrefixForbidden {
            forbidden_prefix: "forbidden:".to_string(),
            known_good_resources: BTreeSet::from(["public:detector-known-good".to_string()]),
            planted_violation_resources: BTreeSet::from(["forbidden:detector-planted".to_string()]),
        };
        let detector = OperationalDetector {
            spec: DetectorSpec {
                id: PUBLIC_RESOURCE_DETECTOR.to_string(),
                evidence_class: EvidenceClass::Substance,
                control_version: "1.0.0".to_string(),
                configuration_digest: detector_rule
                    .configuration_digest()
                    .expect("detector configuration digests"),
                mediation_path: "politeiad.active-operation.dispatcher".to_string(),
                supported_scopes: scopes.clone(),
                calibration_population: detector_rule
                    .calibration_population_digest()
                    .expect("detector calibration population digests"),
                known_blind_spots: vec![
                    "resource prefixes do not infer semantic equivalence".to_string(),
                ],
            },
            rule: detector_rule.clone(),
        };
        let bindings = scopes
            .into_iter()
            .map(|scope| PolicyBinding {
                id: format!("{PUBLIC_RESOURCE_DETECTOR}:{scope}"),
                clause_id: "public-resource-boundary".to_string(),
                detector_ids: vec![PUBLIC_RESOURCE_DETECTOR.to_string()],
                scope,
                authority: enforced_authority(),
            })
            .collect();
        let policy = OperationalPolicyRegistry::new(
            workspace.policy_bundle.clone(),
            bindings,
            BTreeMap::from([(PUBLIC_RESOURCE_DETECTOR.to_string(), detector)]),
        )
        .expect("typed operational policy is coherent");

        let run_authority = assurance_authority(
            fixture,
            &fixture.identities.control_producer,
            RUN_POLICY_CONTROL_ACTION,
            &policy_control_resource(PUBLIC_RESOURCE_DETECTOR),
            Timestamp::now(),
        );
        let activation_authority = assurance_authority(
            fixture,
            &fixture.identities.verifier,
            VERIFY_POLICY_CONTROL_ACTION,
            &policy_control_resource(PUBLIC_RESOURCE_DETECTOR),
            Timestamp::now(),
        );

        let mut capability_evidence = Vec::new();
        let mut capability_admissions = vec![
            delegation_admission(&run_authority),
            delegation_admission(&activation_authority),
        ];
        for (verification, qualification, evidence_observed_at) in [
            (
                local_verification,
                local_qualification,
                local_evidence_observed_at,
            ),
            (
                remote_verification,
                remote_qualification,
                remote_evidence_observed_at,
            ),
        ] {
            let authority = assurance_authority(
                fixture,
                &fixture.identities.verifier,
                VERIFY_EXECUTION_CAPABILITY_ACTION,
                &capability_verification_resource(&verification)
                    .expect("verification resource derives"),
                Timestamp::now(),
            );
            let verification_wire = sign(
                fixture,
                AdmissionKind::Verification,
                &fixture.identities.verifier,
                fixture.identities.verifier_key(),
                verification.clone(),
            );
            let evidence_id = verification
                .evidence
                .iter()
                .next()
                .expect("verification has one evidence identity")
                .clone();
            let qualification_digest = qualification.digest().expect("qualification digests");
            let evidence = sign(
                fixture,
                AdmissionKind::Evidence,
                &fixture.identities.verifier,
                fixture.identities.verifier_key(),
                EvidenceRequest {
                    id: evidence_id,
                    subject: verification.digest().expect("verification digests"),
                    producer_delegation: authority.payload.id.clone(),
                    method: CAPABILITY_QUALIFICATION_METHOD.to_string(),
                    payload_digest: qualification_digest,
                    observed_at: evidence_observed_at,
                    independence: IndependenceClass::IndependentAgent,
                },
            );
            capability_admissions.push(delegation_admission(&authority));
            capability_admissions.push(serde_json::json!({
                "kind": "capability_evidence",
                "submission": CapabilityEvidenceSubmission {
                    verification: verification_wire.clone(),
                    authority: authority.clone(),
                    evidence: vec![evidence],
                    qualification,
                },
            }));
            capability_evidence.push(CapabilityVerificationEvidence {
                verification: verification_wire,
                authority,
            });
        }

        let calibration = policy
            .calibrate_detector(PUBLIC_RESOURCE_DETECTOR)
            .expect("public detector calibration executes");
        let calibration_observed_at = Timestamp::now();
        let calibration_digest = calibration.digest().expect("calibration digests");
        let calibration_evidence_id = EvidenceId::new();
        let calibration_evidence = sign(
            fixture,
            AdmissionKind::Evidence,
            &fixture.identities.verifier,
            fixture.identities.verifier_key(),
            EvidenceRequest {
                id: calibration_evidence_id.clone(),
                subject: calibration_digest.clone(),
                producer_delegation: activation_authority.payload.id.clone(),
                method: DETECTOR_CALIBRATION_METHOD.to_string(),
                payload_digest: calibration_digest,
                observed_at: calibration_observed_at,
                independence: IndependenceClass::IndependentAgent,
            },
        );
        let activation = sign(
            fixture,
            AdmissionKind::ActivationProof,
            &fixture.identities.verifier,
            fixture.identities.verifier_key(),
            calibration
                .activation_proof(EvidenceId::new(), calibration_evidence_id, Timestamp::now())
                .expect("activation proof binds actual detector vectors"),
        );
        capability_admissions.push(serde_json::json!({
            "kind": "detector_calibration_evidence",
            "submission": DetectorCalibrationEvidenceSubmission {
                policy_bytes: policy.artifact_bytes().expect("policy artifact encodes"),
                calibration,
                authority: activation_authority.clone(),
                evidence: calibration_evidence,
            },
        }));

        let policy_bytes = policy.artifact_bytes().expect("policy artifact encodes");
        let execution_bytes = execution
            .artifact_bytes()
            .expect("execution registry artifact encodes");
        fs::write(
            fixture.generation_material.join("policy/constitution.md"),
            &policy_bytes,
        )
        .expect("canonical policy artifact replaces placeholder");
        fs::write(
            fixture
                .generation_material
                .join("components/execution_registry.rs"),
            &execution_bytes,
        )
        .expect("canonical execution registry replaces placeholder");
        fixture.host_trust.workspace.policy_digest = Digest::blake3(&policy_bytes);
        fixture
            .host_trust
            .workspace
            .approved_generation
            .component_digests
            .insert(
                "execution_registry".to_string(),
                Digest::blake3(&execution_bytes),
            );
        fixture.host_trust.bootstrap = sign(
            fixture,
            AdmissionKind::WorkspaceBootstrap,
            &fixture.identities.owner,
            fixture.identities.owner_key(),
            WorkspaceBootstrapRequest {
                workspace: fixture.host_trust.workspace.clone(),
            },
        );

        Self {
            policy,
            execution,
            detector_rule,
            capability_evidence,
            capability_admissions,
            run_authority,
            activation_authority,
            activation,
        }
    }

    /// Canonical policy bytes staged under the generation policy role.
    pub(crate) fn policy_bytes(&self) -> Vec<u8> {
        self.policy
            .artifact_bytes()
            .expect("installed policy remains canonical")
    }

    /// Canonical execution-registry bytes staged as `component:execution_registry`.
    pub(crate) fn execution_registry_bytes(&self) -> Vec<u8> {
        self.execution
            .artifact_bytes()
            .expect("installed execution registry remains canonical")
    }

    /// Exact registered operation selected by its stable semantic name.
    pub(crate) fn operation(&self, name: &str) -> &RegisteredOperation {
        self.execution
            .operation_named(name)
            .expect("requested operation is present in the fixture registry")
    }

    /// Operation identities disclosed by active-generation discovery.
    pub(crate) fn operation_ids(&self) -> BTreeSet<OperationId> {
        self.execution
            .capability_inventory()
            .operations
            .into_iter()
            .map(|operation| operation.spec.id)
            .collect()
    }

    /// Execution-resource identities disclosed by active-generation discovery.
    pub(crate) fn resource_ids(&self) -> BTreeSet<ExecutionResourceId> {
        self.execution
            .capability_inventory()
            .resources
            .into_iter()
            .map(|resource| resource.id)
            .collect()
    }

    /// Exact population digest used by active capability discovery.
    pub(crate) fn capability_population_digest(&self) -> Digest {
        Digest::blake3(
            &to_canonical_bytes(&(self.operation_ids(), self.resource_ids()))
                .expect("capability population encodes"),
        )
    }

    /// Availability observation naming both the eligible local resource and
    /// cheaper, higher-scoring but hard-ineligible remote reference resource.
    pub(crate) fn availability(&self, at: Timestamp) -> AvailabilitySnapshot {
        AvailabilitySnapshot {
            observed_at: at,
            expires_at: at + SignedDuration::from_mins(10),
            available_resources: self.execution.available_resources().clone(),
        }
    }

    /// Daemon commissioning requests required before any active operation.
    ///
    /// Callers must issue these in order via the public CLI. Grants precede the
    /// capability and calibration evidence whose commits recheck them.
    pub(crate) fn admission_requests(&self) -> Vec<serde_json::Value> {
        self.capability_admissions.clone()
    }

    /// Build an exact signed operation submission around an already admitted
    /// root-to-leaf requester authority chain.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixture keeps each authenticated operation axis explicit"
    )]
    pub(crate) fn submission(
        &self,
        fixture: &ReferenceFixture,
        operation_name: &str,
        requester: &PrincipalId,
        requester_key: &SigningKey,
        input_digest: Digest,
        delegation_chain: Vec<Delegation>,
        resources: BTreeSet<String>,
        budget: ResourceBudget,
        at: Timestamp,
        idempotency_key: Option<String>,
    ) -> OperationSubmission {
        let registered = self.operation(operation_name);
        let availability = self.availability(at);
        let inventory = self.execution.capability_inventory();
        let mut routing = Router::route(
            &registered.requirement,
            inventory.resources,
            inventory.profiles,
            inventory.verifications,
            &availability,
            at,
        )
        .expect("fixture routing inputs are coherent");
        routing.id = RoutingDecisionId::new();
        let assignment = routing
            .assignment()
            .expect("routing receipt encodes")
            .expect("eligible local deterministic resource is selected");
        let intent = OperationIntent {
            principal: requester.clone(),
            input_digest,
            delegation_chain,
            operation: registered.spec.clone(),
            resources,
            budget,
            idempotency_key,
            execution: Some(assignment),
        };
        let intent_digest = intent.digest().expect("operation intent digests");
        let control_started_at = Timestamp::now();
        let mut run = self
            .policy
            .run_control(
                &OperationalEvaluationRequest {
                    institution: fixture.host_trust.workspace.institution.clone(),
                    workspace: fixture.host_trust.workspace.id.clone(),
                    intent_digest,
                    principal: requester.clone(),
                    operation: registered.spec.clone(),
                    resources: intent.resources.clone(),
                    at,
                },
                EvidenceId::new(),
                PUBLIC_RESOURCE_DETECTOR,
                Digest::blake3(
                    &to_canonical_bytes(&self.run_authority.payload)
                        .expect("control authority encodes"),
                ),
                control_started_at,
                control_started_at,
            )
            .expect("public detector executes");
        run.finished_at = Timestamp::now();
        OperationSubmission {
            intent: sign(
                fixture,
                AdmissionKind::OperationIntent,
                requester,
                requester_key,
                intent,
            ),
            availability,
            routing,
            capability_verifications: self.capability_evidence.clone(),
            assurance: vec![OperationalControlEvidence {
                run: sign(
                    fixture,
                    AdmissionKind::ControlRun,
                    &fixture.identities.control_producer,
                    fixture.identities.control_producer_key(),
                    run,
                ),
                run_authority: self.run_authority.clone(),
                activation: self.activation.clone(),
                activation_authority: self.activation_authority.clone(),
            }],
        }
    }

    /// Positive local manifest canary and its exact owner grant admission.
    pub(crate) fn positive_manifest(
        &self,
        fixture: &ReferenceFixture,
        at: Timestamp,
    ) -> PreparedManifestOperation {
        self.manifest_case(fixture, at, "public:approved-operation")
    }

    /// Planted forbidden-resource canary. Routing remains valid and policy
    /// itself must return the exact denial reason without reserving an effect.
    pub(crate) fn negative_manifest(
        &self,
        fixture: &ReferenceFixture,
        at: Timestamp,
    ) -> PreparedManifestOperation {
        self.manifest_case(fixture, at, PLANTED_FORBIDDEN_RESOURCE)
    }

    fn manifest_case(
        &self,
        fixture: &ReferenceFixture,
        at: Timestamp,
        resource: &str,
    ) -> PreparedManifestOperation {
        let resources = BTreeSet::from([resource.to_string()]);
        let budget = operation_budget();
        let grant = operation_authority(
            fixture,
            &fixture.identities.worker,
            &self.operation(RESOURCE_MANIFEST_OPERATION).spec,
            resources.clone(),
            budget.clone(),
            at,
        );
        let submission = self.submission(
            fixture,
            RESOURCE_MANIFEST_OPERATION,
            &fixture.identities.worker,
            fixture.identities.worker_key(),
            Digest::blake3(
                &to_canonical_bytes(&(RESOURCE_MANIFEST_OPERATION, &resources))
                    .expect("manifest input encodes"),
            ),
            vec![grant.payload.clone()],
            resources,
            budget,
            at,
            None,
        );
        PreparedManifestOperation {
            authority_admission: delegation_admission(&grant),
            operate: serde_json::to_value(submission).expect("operation submission serializes"),
        }
    }

    /// Hard rejection reasons expected for the cheaper remote resource.
    pub(crate) fn remote_rejections(&self, at: Timestamp) -> BTreeSet<RoutingRejection> {
        let registered = self.operation(RESOURCE_MANIFEST_OPERATION);
        let inventory = self.execution.capability_inventory();
        let decision = Router::route(
            &registered.requirement,
            inventory.resources.clone(),
            inventory.profiles,
            inventory.verifications,
            &self.availability(at),
            at,
        )
        .expect("fixture routing executes");
        let remote = inventory
            .resources
            .iter()
            .find(|resource| resource.locality == ExecutionLocality::ProviderRemote)
            .expect("remote reference resource exists");
        decision
            .rejected_resources
            .get(&remote.id)
            .expect("remote reference resource is hard rejected")
            .clone()
    }
}

fn registered_operations(trust_domain: &TrustDomainId) -> Vec<RegisteredOperation> {
    vec![
        registered_operation(
            RESOURCE_MANIFEST_OPERATION,
            BTreeSet::from([RESOURCE_MANIFEST_ACTION.to_string()]),
            BTreeSet::from([Effect::CreateArtifact]),
            BTreeSet::from([DataClass::Public]),
            vec![OPERATION_RECEIPT_OBLIGATION.to_string()],
            InstalledOperationHandler::ResourceManifest {
                maximum_resources: 8,
                maximum_resource_bytes: 4_096,
            },
            trust_domain,
            false,
        ),
        registered_operation(
            CAPTURE_SOURCE_OPERATION,
            BTreeSet::from([RECONNOITRE_ACTION.to_string()]),
            BTreeSet::from([Effect::ReadExternalSystem]),
            BTreeSet::from([DataClass::Internal]),
            vec!["source-capture-receipt".to_string()],
            InstalledOperationHandler::CaptureAuthorizedSource,
            trust_domain,
            false,
        ),
        registered_operation(
            COMPILE_CONTEXT_OPERATION,
            BTreeSet::from([COMPILE_CONTEXT_ACTION.to_string()]),
            BTreeSet::from([CONTEXT_READ_EFFECT]),
            BTreeSet::from([DataClass::Internal]),
            vec!["learning-disclosure-receipt".to_string()],
            InstalledOperationHandler::CompileInstitutionalContext,
            trust_domain,
            true,
        ),
        registered_operation(
            DISCOVER_CAPABILITIES_OPERATION,
            BTreeSet::from([DISCOVER_CAPABILITIES_ACTION.to_string()]),
            BTreeSet::from([CONTEXT_READ_EFFECT]),
            BTreeSet::from([DataClass::Internal]),
            vec!["learning-discovery-receipt".to_string()],
            InstalledOperationHandler::DiscoverInstitutionalCapabilities,
            trust_domain,
            true,
        ),
    ]
}

#[expect(
    clippy::too_many_arguments,
    reason = "an operation contract keeps each authorization axis explicit"
)]
fn registered_operation(
    name: &str,
    actions: BTreeSet<String>,
    effects: BTreeSet<Effect>,
    data_classes: BTreeSet<DataClass>,
    evidence_obligations: Vec<String>,
    handler: InstalledOperationHandler,
    trust_domain: &TrustDomainId,
    requires_idempotency: bool,
) -> RegisteredOperation {
    let requirement = ExecutionRequirement {
        task_class: BOUNDED_LOCAL_OPERATION_TASK_CLASS.to_string(),
        required_capabilities: BTreeSet::from([BOUNDED_LOCAL_OPERATION_CAPABILITY.to_string()]),
        required_effects: effects.clone(),
        data_classes: data_classes.clone(),
        allowed_localities: BTreeSet::from([ExecutionLocality::ClientLocal]),
        allowed_trust_domains: BTreeSet::from([trust_domain.clone()]),
        minimum_context_tokens: 1,
        maximum_cost_microunits: Some(10_000),
        maximum_latency_ms: Some(5_000),
        require_independent_result_verification: false,
        deterministic_only: true,
        preferences: vec![
            SoftPreference::MinimizeCost,
            SoftPreference::MinimizeLatency,
        ],
    };
    let requirement_digest = requirement.digest().expect("execution requirement digests");
    RegisteredOperation {
        spec: OperationSpec {
            id: OperationId::new(),
            name: name.to_string(),
            actions,
            effects,
            data_classes,
            evidence_obligations,
            execution_requirement: Some(requirement_digest),
            retryable: false,
            requires_idempotency,
        },
        requirement,
        handler,
    }
}

fn capability_profile(verification: &CapabilityVerificationRecord) -> CapabilityProfile {
    CapabilityProfile {
        id: verification.profile.clone(),
        resource: verification.resource.clone(),
        resource_digest: verification.resource_digest.clone(),
        task_classes: verification.task_classes.clone(),
        capabilities: verification.capabilities.clone(),
        verification: verification.id.clone(),
        verification_digest: verification.digest().expect("verification digests"),
    }
}

/// Execute the public probe before fixing the signed observation time.
///
/// The profile digest includes the verification record, so a provisional
/// record is needed to run the probe without predicting its completion time.
/// Only the probe result survives that provisional record. The returned
/// verification/profile pair is bound to the timestamp captured immediately
/// after the actual probe, and that same instant is signed by its evidence.
fn qualified_capability_material(
    mut verification: CapabilityVerificationRecord,
    resource: &ExecutionResource,
    manifest_operation: Option<&RegisteredOperation>,
) -> (
    CapabilityVerificationRecord,
    CapabilityProfile,
    CapabilityQualificationEvidence,
    Timestamp,
) {
    let provisional_profile = capability_profile(&verification);
    let observed = CapabilityQualificationEvidence::reproduce(
        &verification,
        resource,
        &provisional_profile,
        manifest_operation,
    )
    .expect("public capability qualification executes");
    let evidence_observed_at = Timestamp::now();
    verification.observed_at = evidence_observed_at;
    verification.expires_at = evidence_observed_at + SignedDuration::from_hours(2);
    let profile = capability_profile(&verification);
    let qualification = CapabilityQualificationEvidence {
        schema: observed.schema,
        verification: verification.id.clone(),
        resource: resource.clone(),
        profile: profile.clone(),
        probe: observed.probe,
    };
    (verification, profile, qualification, evidence_observed_at)
}

fn enforced_authority() -> BindingAuthority {
    let mut ladder = HardeningLadder::new();
    for state in [
        HardeningState::Observed,
        HardeningState::Proposed,
        HardeningState::Approved,
        HardeningState::Shadow,
        HardeningState::Calibrated,
        HardeningState::Advisory,
        HardeningState::Enforced,
    ] {
        ladder.advance(state).expect("fixture ladder edge is legal");
    }
    BindingAuthority::new(ladder, Consequence::Deny).expect("enforced binding authorizes denial")
}

fn assurance_authority(
    fixture: &ReferenceFixture,
    subject: &PrincipalId,
    action: &str,
    resource: &str,
    at: Timestamp,
) -> SignedAdmissionWire<Delegation> {
    let delegation = Delegation {
        id: DelegationId::new(),
        issuer: fixture.identities.owner.clone(),
        subject: subject.clone(),
        parent: None,
        actions: BTreeSet::from([action.to_string()]),
        resources: BTreeSet::from([resource.to_string()]),
        effects: BTreeSet::new(),
        data_classes: BTreeSet::new(),
        audience: BTreeSet::from([institution_audience(
            &fixture.host_trust.workspace.institution,
        )]),
        expires_at: at + SignedDuration::from_hours(2),
        budget: operation_budget(),
    };
    sign(
        fixture,
        AdmissionKind::Delegation,
        &fixture.identities.owner,
        fixture.identities.owner_key(),
        delegation,
    )
}

fn operation_authority(
    fixture: &ReferenceFixture,
    subject: &PrincipalId,
    operation: &OperationSpec,
    resources: BTreeSet<String>,
    budget: ResourceBudget,
    at: Timestamp,
) -> SignedAdmissionWire<Delegation> {
    sign(
        fixture,
        AdmissionKind::Delegation,
        &fixture.identities.owner,
        fixture.identities.owner_key(),
        Delegation {
            id: DelegationId::new(),
            issuer: fixture.identities.owner.clone(),
            subject: subject.clone(),
            parent: None,
            actions: operation.actions.clone(),
            resources,
            effects: operation.effects.clone(),
            data_classes: operation.data_classes.clone(),
            audience: BTreeSet::from([institution_audience(
                &fixture.host_trust.workspace.institution,
            )]),
            expires_at: at + SignedDuration::from_hours(1),
            budget,
        },
    )
}

fn operation_budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(30_000),
        cpu_ms: Some(10_000),
        memory_bytes: Some(64 * 1024 * 1024),
        io_bytes: Some(1024 * 1024),
        network_bytes: Some(1024 * 1024),
        external_cost_microunits: Some(10_000),
    }
}

fn delegation_admission(wire: &SignedAdmissionWire<Delegation>) -> serde_json::Value {
    serde_json::json!({
        "kind": "admit_delegation",
        "delegation": wire,
    })
}

fn trust_domain(value: &str) -> TrustDomainId {
    value.parse().expect("fixture trust domain is canonical")
}

fn sign<T: serde::Serialize>(
    fixture: &ReferenceFixture,
    kind: AdmissionKind,
    signer: &PrincipalId,
    key: &SigningKey,
    payload: T,
) -> SignedAdmissionWire<T> {
    SignedAdmissionWire::sign(
        kind,
        fixture.host_trust.workspace.institution.clone(),
        fixture.host_trust.workspace.id.clone(),
        signer.clone(),
        payload,
        key,
    )
    .expect("fixture signing input is canonical")
}
