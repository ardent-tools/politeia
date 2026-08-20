use jiff::SignedDuration;

use super::*;

#[expect(
    clippy::expect_used,
    reason = "routing fixtures use canonical trust-domain identifiers"
)]
fn trust_domain() -> TrustDomainId {
    "client-a:production"
        .parse()
        .expect("fixture trust domain is canonical")
}

#[expect(
    clippy::expect_used,
    reason = "routing fixtures use a distinct canonical verifier control domain"
)]
fn verifier() -> (PrincipalId, TrustDomainId) {
    (
        PrincipalId::new(),
        "verifier-a:assurance"
            .parse()
            .expect("fixture verifier domain is canonical"),
    )
}

fn resource(
    locality: ExecutionLocality,
    descriptor: ExecutionResourceDescriptor,
    cost: u64,
) -> ExecutionResource {
    let trust_domain = trust_domain();
    ExecutionResource {
        id: ExecutionResourceId::new(),
        descriptor,
        adapter: AdapterId::new(),
        trust_domain: trust_domain.clone(),
        control_domain: trust_domain,
        locality,
        allowed_data_classes: BTreeSet::from([DataClass::Public, DataClass::Confidential]),
        allowed_effects: BTreeSet::from([Effect::ReadExternalSystem]),
        max_context_tokens: 16_000,
        estimated_cost_microunits: cost,
        estimated_latency_ms: 100,
    }
}

#[expect(
    clippy::expect_used,
    reason = "routing fixtures must bind profiles to canonical resource bytes"
)]
fn profile(
    resource: &ExecutionResource,
    capability: &str,
    verifier: &(PrincipalId, TrustDomainId),
    now: Timestamp,
) -> (CapabilityProfile, CapabilityVerificationRecord) {
    let profile_id = CapabilityProfileId::new();
    let resource_digest = resource.digest().expect("fixture resource encodes");
    let task_classes = BTreeSet::from(["bounded_read".to_string()]);
    let capabilities = BTreeSet::from([capability.to_string()]);
    let verification = CapabilityVerificationRecord {
        id: CapabilityVerificationId::new(),
        profile: profile_id.clone(),
        resource: resource.id.clone(),
        resource_digest: resource_digest.clone(),
        task_classes: task_classes.clone(),
        capabilities: capabilities.clone(),
        verifier: verifier.0.clone(),
        verifier_control_domain: verifier.1.clone(),
        evidence: BTreeSet::from([EvidenceId::new()]),
        observed_at: now,
        expires_at: now + SignedDuration::from_hours(1),
    };
    let profile = CapabilityProfile {
        id: profile_id,
        resource: resource.id.clone(),
        resource_digest,
        task_classes,
        capabilities,
        verification: verification.id.clone(),
        verification_digest: verification.digest().expect("fixture verification encodes"),
    };
    (profile, verification)
}

fn requirement(localities: BTreeSet<ExecutionLocality>) -> ExecutionRequirement {
    ExecutionRequirement {
        task_class: "bounded_read".to_string(),
        required_capabilities: BTreeSet::from(["read_source".to_string()]),
        required_effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes: BTreeSet::from([DataClass::Confidential]),
        allowed_localities: localities,
        allowed_trust_domains: BTreeSet::from([trust_domain()]),
        minimum_context_tokens: 1_000,
        maximum_cost_microunits: Some(1_000),
        maximum_latency_ms: Some(1_000),
        require_independent_result_verification: true,
        deterministic_only: false,
        preferences: vec![SoftPreference::PreferLocal, SoftPreference::MinimizeCost],
    }
}

fn snapshot(resources: &[&ExecutionResource], now: Timestamp) -> AvailabilitySnapshot {
    AvailabilitySnapshot {
        observed_at: now,
        expires_at: now + SignedDuration::from_mins(5),
        available_resources: resources
            .iter()
            .map(|resource| resource.id.clone())
            .collect(),
    }
}

fn selected(decision: &RoutingDecision) -> Option<&ExecutionResourceId> {
    match &decision.outcome {
        RoutingOutcome::Selected { resource, .. } => Some(resource),
        RoutingOutcome::Escalate => None,
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "valid routing fixtures must produce a decision"
)]
fn hard_filtering_precedes_ordered_locality_and_cost_preferences() {
    let local = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Model {
            provider: "client".to_string(),
            model: "local-model-v1".to_string(),
            runtime: "client-runtime-v1".to_string(),
            harness: "client-harness-v1".to_string(),
        },
        20,
    );
    let remote = resource(
        ExecutionLocality::ClientRemote,
        ExecutionResourceDescriptor::Model {
            provider: "client".to_string(),
            model: "remote-model-v1".to_string(),
            runtime: "remote-runtime-v1".to_string(),
            harness: "remote-harness-v1".to_string(),
        },
        10,
    );
    let now = Timestamp::now();
    let verifier = verifier();
    let (local_profile, local_verification) = profile(&local, "read_source", &verifier, now);
    let (remote_profile, remote_verification) = profile(&remote, "read_source", &verifier, now);
    let decision = Router::route(
        &requirement(BTreeSet::from([
            ExecutionLocality::ClientLocal,
            ExecutionLocality::ClientRemote,
        ])),
        [local.clone(), remote.clone()],
        [local_profile, remote_profile],
        [local_verification, remote_verification],
        &snapshot(&[&local, &remote], now),
        now,
    )
    .expect("routing inputs are valid");
    assert_eq!(
        selected(&decision),
        Some(&local.id),
        "the first soft preference must win before the cheaper second preference"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "valid locality fixtures must produce a decision"
)]
fn hard_locality_rejects_a_cheaper_remote_resource() {
    let local = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Service {
            service: "client-reader-v1".to_string(),
        },
        30,
    );
    let remote = resource(
        ExecutionLocality::ProviderRemote,
        ExecutionResourceDescriptor::Service {
            service: "provider-reader-v1".to_string(),
        },
        1,
    );
    let now = Timestamp::now();
    let verifier = verifier();
    let (local_profile, local_verification) = profile(&local, "read_source", &verifier, now);
    let (remote_profile, remote_verification) = profile(&remote, "read_source", &verifier, now);
    let decision = Router::route(
        &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
        [local.clone(), remote.clone()],
        [local_profile, remote_profile],
        [local_verification, remote_verification],
        &snapshot(&[&local, &remote], now),
        now,
    )
    .expect("routing inputs are valid");
    assert_eq!(selected(&decision), Some(&local.id));
    assert!(
        decision
            .rejected_resources
            .get(&remote.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::LocalityForbidden)),
        "the remote resource must retain an explicit hard-rejection reason"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "valid deterministic-tool fixtures must produce a decision"
)]
fn deterministic_requirement_never_selects_an_available_model() {
    let tool = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::DeterministicTool {
            artifact_digest: Digest::blake3(b"tool"),
            version: "1.0.0".to_string(),
        },
        5,
    );
    let model = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Model {
            provider: "client".to_string(),
            model: "model-v1".to_string(),
            runtime: "runtime-v1".to_string(),
            harness: "harness-v1".to_string(),
        },
        1,
    );
    let mut requirement = requirement(BTreeSet::from([ExecutionLocality::ClientLocal]));
    requirement.deterministic_only = true;
    let now = Timestamp::now();
    let verifier = verifier();
    let (tool_profile, tool_verification) = profile(&tool, "read_source", &verifier, now);
    let (model_profile, model_verification) = profile(&model, "read_source", &verifier, now);
    let decision = Router::route(
        &requirement,
        [tool.clone(), model.clone()],
        [tool_profile, model_profile],
        [tool_verification, model_verification],
        &snapshot(&[&tool, &model], now),
        now,
    )
    .expect("routing inputs are valid");
    assert_eq!(selected(&decision), Some(&tool.id));
    assert!(
        decision
            .rejected_resources
            .get(&model.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::DeterministicToolRequired)),
        "model availability must not weaken a deterministic hard requirement"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "valid escalation fixtures must produce a decision"
)]
fn missing_hard_capability_escalates_instead_of_selecting_closest() {
    let resource = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Human {
            principal: PrincipalId::new(),
        },
        1,
    );
    let now = Timestamp::now();
    let verifier = verifier();
    let (profile, verification) = profile(&resource, "different_capability", &verifier, now);
    let decision = Router::route(
        &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
        [resource.clone()],
        [profile],
        [verification],
        &snapshot(&[&resource], now),
        now,
    )
    .expect("routing inputs are valid");
    assert!(matches!(decision.outcome, RoutingOutcome::Escalate));
    assert!(decision.eligible_resources.is_empty());
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "self-verification fixture uses canonical control-domain identities"
)]
fn self_verified_or_stale_capability_evidence_is_ineligible() {
    let tool = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::DeterministicTool {
            artifact_digest: Digest::blake3(b"tool"),
            version: "1.0.0".to_string(),
        },
        1,
    );
    let now = Timestamp::now();
    let self_verifier = (PrincipalId::new(), tool.control_domain.clone());
    let (self_profile, self_verification) = profile(&tool, "read_source", &self_verifier, now);
    let mut no_result_verification = requirement(BTreeSet::from([ExecutionLocality::ClientLocal]));
    no_result_verification.require_independent_result_verification = false;
    let decision = Router::route(
        &no_result_verification,
        [tool.clone()],
        [self_profile],
        [self_verification],
        &snapshot(&[&tool], now),
        now,
    )
    .expect("routing inputs are structurally valid");
    assert!(
        !decision.independent_verification_required,
        "result-verification obligations must remain distinct from capability admission"
    );
    assert!(
        decision
            .rejected_resources
            .get(&tool.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::SelfVerifiedCapability)),
        "a resource cannot certify its own independent capability evidence"
    );

    let verifier = verifier();
    let (mut stale_profile, mut stale_verification) = profile(&tool, "read_source", &verifier, now);
    stale_verification.expires_at = now;
    stale_profile.verification_digest = stale_verification
        .digest()
        .expect("stale verification still encodes");
    let stale_decision = Router::route(
        &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
        [tool.clone()],
        [stale_profile],
        [stale_verification],
        &snapshot(&[&tool], now),
        now,
    )
    .expect("stale evidence is a typed rejection, not malformed input");
    assert!(
        stale_decision
            .rejected_resources
            .get(&tool.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::StaleCapabilityEvidence))
    );

    let human = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Human {
            principal: verifier.0.clone(),
        },
        1,
    );
    let (human_profile, human_verification) = profile(&human, "read_source", &verifier, now);
    let human_decision = Router::route(
        &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
        [human.clone()],
        [human_profile],
        [human_verification],
        &snapshot(&[&human], now),
        now,
    )
    .expect("human self-verification is a typed rejection");
    assert!(
        human_decision
            .rejected_resources
            .get(&human.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::SelfVerifiedCapability)),
        "a human resource cannot verify itself under a relabeled control domain"
    );

    let (profile, mut mismatched_verification) = profile(&tool, "read_source", &verifier, now);
    mismatched_verification
        .capabilities
        .insert("caller_asserted_capability".to_string());
    let mismatch_decision = Router::route(
        &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
        [tool.clone()],
        [profile],
        [mismatched_verification],
        &snapshot(&[&tool], now),
        now,
    )
    .expect("mismatched trusted receipt is a typed rejection");
    assert!(
        mismatch_decision
            .rejected_resources
            .get(&tool.id)
            .is_some_and(|reasons| reasons.contains(&RoutingRejection::VerifierNotAdmitted)),
        "a profile cannot rewrite the exact trusted verification claim"
    );
}

#[test]
fn tagged_variants_reject_unknown_fields() {
    const ESCALATE: &str = r#"{"status":"escalate"}"#;
    let json = r#"{
        "kind":"deterministic_tool",
        "artifact_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "version":"1.0.0",
        "ambient_authority":true
    }"#;
    assert!(serde_json::from_str::<ExecutionResourceDescriptor>(json).is_err());
    assert!(matches!(
        serde_json::from_str::<RoutingOutcome>(ESCALATE),
        Ok(RoutingOutcome::Escalate)
    ));
    assert!(matches!(
        serde_json::to_string(&RoutingOutcome::Escalate).as_deref(),
        Ok(ESCALATE)
    ));
    assert!(
        serde_json::from_str::<RoutingOutcome>(r#"{"status":"escalate","ambient_authority":true}"#)
            .is_err(),
        "tagged routing outcomes must reject variant-local unknown fields"
    );
    assert!(
        serde_json::from_str::<RoutingOutcome>(r#"["escalate"]"#).is_err(),
        "schema-invalid sequence representations must fail closed"
    );
    assert!(
        serde_json::from_str::<RoutingOutcome>(
            r#"{"status":"escalate","resource":"substitution"}"#
        )
        .is_err(),
        "fields from the selected variant must fail on escalation"
    );
    assert!(
        serde_json::from_str::<RoutingOutcome>(r#"{"status":"escalate","status":"escalate"}"#)
            .is_err(),
        "duplicate variant tags must fail closed"
    );
}

#[test]
fn capability_profile_identity_is_globally_unique() {
    let first = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Service {
            service: "first".to_string(),
        },
        1,
    );
    let second = resource(
        ExecutionLocality::ClientLocal,
        ExecutionResourceDescriptor::Service {
            service: "second".to_string(),
        },
        2,
    );
    let now = Timestamp::now();
    let verifier = verifier();
    let (first_profile, first_verification) = profile(&first, "read_source", &verifier, now);
    let (mut second_profile, second_verification) = profile(&second, "read_source", &verifier, now);
    second_profile.id = first_profile.id.clone();

    assert!(matches!(
        Router::route(
            &requirement(BTreeSet::from([ExecutionLocality::ClientLocal])),
            [first.clone(), second.clone()],
            [first_profile, second_profile],
            [first_verification, second_verification],
            &snapshot(&[&first, &second], now),
            now,
        ),
        Err(RoutingError::DuplicateCapabilityProfileId)
    ));
}
