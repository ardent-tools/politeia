#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the routed vertical-slice fixture must bind exact canonical identities"
)]
async fn routing_assignment_is_bound_through_policy_lease_and_effect() {
    let mut fixture = fixture();
    let trust_domain: TrustDomainId = "client-a:production"
        .parse()
        .expect("fixture trust domain is canonical");
    let resource = ExecutionResource {
        id: ExecutionResourceId::new(),
        descriptor: ExecutionResourceDescriptor::DeterministicTool {
            artifact_digest: Digest::blake3(b"bounded reader"),
            version: "1.0.0".to_string(),
        },
        adapter: fixture.dispatcher.adapter.clone(),
        trust_domain: trust_domain.clone(),
        control_domain: trust_domain.clone(),
        locality: ExecutionLocality::ClientLocal,
        allowed_data_classes: BTreeSet::from([DataClass::Public]),
        allowed_effects: BTreeSet::from([Effect::ReadExternalSystem]),
        max_context_tokens: 4_000,
        estimated_cost_microunits: 0,
        estimated_latency_ms: 10,
    };
    let profile_id = CapabilityProfileId::new();
    let resource_digest = resource.digest().expect("fixture resource encodes");
    let task_classes = BTreeSet::from(["bounded_read".to_string()]);
    let capabilities = BTreeSet::from(["read_source".to_string()]);
    let verification = CapabilityVerificationRecord {
        id: CapabilityVerificationId::new(),
        profile: profile_id.clone(),
        resource: resource.id.clone(),
        resource_digest: resource_digest.clone(),
        task_classes: task_classes.clone(),
        capabilities: capabilities.clone(),
        verifier: PrincipalId::new(),
        verifier_control_domain: "verifier-a:assurance"
            .parse()
            .expect("fixture verifier domain is canonical"),
        evidence: BTreeSet::from([EvidenceId::new()]),
        observed_at: fixture.now,
        expires_at: fixture.now + SignedDuration::from_hours(1),
    };
    let profile = CapabilityProfile {
        id: profile_id,
        resource: resource.id.clone(),
        resource_digest,
        task_classes,
        capabilities,
        verification: verification.id.clone(),
        verification_digest: verification.digest().expect("verification record encodes"),
    };
    let requirement = ExecutionRequirement {
        task_class: "bounded_read".to_string(),
        required_capabilities: BTreeSet::from(["read_source".to_string()]),
        required_effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes: BTreeSet::from([DataClass::Public]),
        allowed_localities: BTreeSet::from([ExecutionLocality::ClientLocal]),
        allowed_trust_domains: BTreeSet::from([trust_domain]),
        minimum_context_tokens: 1,
        maximum_cost_microunits: Some(0),
        maximum_latency_ms: Some(100),
        require_independent_result_verification: true,
        deterministic_only: true,
        preferences: vec![SoftPreference::PreferLocal, SoftPreference::MinimizeCost],
    };
    let snapshot = AvailabilitySnapshot {
        observed_at: fixture.now,
        expires_at: fixture.now + SignedDuration::from_mins(5),
        available_resources: BTreeSet::from([resource.id.clone()]),
    };
    let decision = Router::route(
        &requirement,
        [resource.clone()],
        [profile],
        [verification],
        &snapshot,
        fixture.now,
    )
    .expect("routing fixture is valid");
    assert!(matches!(&decision.outcome, RoutingOutcome::Selected { .. }));
    let assignment = decision
        .assignment()
        .expect("routing decision encodes")
        .expect("selected routing decision projects an assignment");
    fixture.intent.operation.execution_requirement =
        Some(requirement.digest().expect("requirement encodes"));
    fixture.intent.execution = Some(assignment.clone());
    fixture.dispatcher.config = DispatcherConfig::new(
        fixture.dispatcher.config.policy_bundle.clone(),
        fixture.dispatcher.config.policy_digest.clone(),
        fixture.dispatcher.config.runtime.clone(),
        fixture.dispatcher.config.replay_domain.clone(),
        fixture.dispatcher.config.max_lease_ttl,
        fixture.intent.delegation_chain.clone(),
        [fixture.intent.operation.clone()],
    )
    .expect("routed dispatcher configuration is valid")
    .with_trusted_routing_decisions([decision])
    .expect("the exact selected routing decision is admitted");

    for substituted in [
        {
            let mut substituted = assignment.clone();
            substituted.resource = ExecutionResourceId::new();
            substituted
        },
        {
            let mut substituted = assignment.clone();
            substituted.capability_profile = CapabilityProfileId::new();
            substituted
        },
        {
            let mut substituted = assignment.clone();
            substituted.trust_domain = "client-b:production"
                .parse()
                .expect("substitution domain is canonical");
            substituted
        },
        {
            let mut substituted = assignment.clone();
            substituted.routing_decision_digest = Digest::blake3(b"substituted receipt");
            substituted
        },
    ] {
        fixture.intent.execution = Some(substituted);
        assert!(matches!(
            fixture.dispatcher.authorize(&fixture.intent).await,
            Err(RuntimeError::InvalidExecutionAssignment { .. })
        ));
    }
    fixture.intent.execution = Some(assignment.clone());

    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("routed intent authorizes");
    assert_eq!(
        lease.execution(),
        Some(&assignment),
        "policy and lease must bind the exact selected resource and routing receipt"
    );
    fixture
        .dispatcher
        .execute(&lease)
        .await
        .expect("bound routed operation executes through the registered port");
    assert_eq!(fixture.dispatcher.port.call_count(), 1);
}
#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "expired assignment fixture uses canonical trust-domain identities"
)]
async fn fabricated_routing_assignment_fails_before_policy_or_effect() {
    let mut fixture = fixture();
    let requirement_digest = Digest::blake3(b"required routing contract");
    fixture.intent.operation.execution_requirement = Some(requirement_digest.clone());
    fixture.dispatcher.config.trusted_operations.insert(
        fixture.intent.operation.id.clone(),
        fixture.intent.operation.clone(),
    );
    fixture.intent.execution = Some(routing::ExecutionAssignment {
        resource: ExecutionResourceId::new(),
        resource_digest: Digest::blake3(b"resource"),
        adapter: fixture.dispatcher.adapter.clone(),
        trust_domain: "client-a:production"
            .parse()
            .expect("fixture trust domain is canonical"),
        control_domain: "client-a:production"
            .parse()
            .expect("fixture trust domain is canonical"),
        locality: ExecutionLocality::ClientLocal,
        capability_profile: CapabilityProfileId::new(),
        capability_profile_digest: Digest::blake3(b"profile"),
        routing_decision: RoutingDecisionId::new(),
        requirement_digest,
        routing_decision_digest: Digest::blake3(b"decision"),
        availability_snapshot_digest: Digest::blake3(b"availability"),
        expires_at: fixture.now + SignedDuration::from_mins(5),
    });

    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(matches!(
        result,
        Err(RuntimeError::InvalidExecutionAssignment { .. })
    ));
    assert_eq!(fixture.dispatcher.port.call_count(), 0);
}

#[tokio::test]
async fn routing_required_operation_cannot_omit_its_assignment() {
    let mut fixture = fixture();
    fixture.intent.operation.execution_requirement = Some(Digest::blake3(b"routing requirement"));
    fixture.dispatcher.config.trusted_operations.insert(
        fixture.intent.operation.id.clone(),
        fixture.intent.operation.clone(),
    );

    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(matches!(
        result,
        Err(RuntimeError::InvalidExecutionAssignment { .. })
    ));
    assert_eq!(fixture.dispatcher.port.call_count(), 0);
}
