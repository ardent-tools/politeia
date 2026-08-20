#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the valid fixture must mint a lease before simulated time advances"
)]
async fn lease_expiry_is_rechecked_at_effect_time() {
    let fixture = fixture();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the valid fixture must authorize");

    fixture
        .dispatcher
        .ledger
        .set_observed_at(fixture.now + SignedDuration::from_hours(2))
        .await;
    let result = fixture.dispatcher.execute(&lease).await;
    assert!(
        matches!(result, Err(RuntimeError::LeaseExpired { .. })),
        "a lease that expires after minting must fail at effect time"
    );
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        0,
        "an expired lease must not reach the effect port"
    );
}
#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the valid fixture must mint a lease before audience substitution"
)]
async fn wrong_audience_fails_before_effect_invocation() {
    let mut fixture = fixture();
    fixture.dispatcher.port.audience = "effect-port:network".to_string();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the valid fixture must authorize");

    let result = fixture.dispatcher.execute(&lease).await;
    assert!(
        matches!(result, Err(RuntimeError::WrongAudience { .. })),
        "a port outside the delegated audience must fail closed"
    );
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        0,
        "the wrong audience must not reach the effect port"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the valid fixture must mint the lease used by both contenders"
)]
async fn concurrent_replay_allows_only_one_effect() {
    let fixture = fixture();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the valid fixture must authorize");

    let (left, right) = tokio::join!(
        fixture.dispatcher.execute(&lease),
        fixture.dispatcher.execute(&lease),
    );
    let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
    let replays = usize::from(matches!(left, Err(RuntimeError::ReplayDetected { .. })))
        + usize::from(matches!(right, Err(RuntimeError::ReplayDetected { .. })));
    assert_eq!(successes, 1, "exactly one concurrent use must succeed");
    assert_eq!(replays, 1, "the competing use must be rejected as replay");
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        1,
        "concurrent reuse must invoke the effect port only once"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "handoff requires a valid reserved lease and equivalent trusted config"
)]
async fn shared_ledger_allows_dispatcher_handoff_but_only_one_claim() {
    let fixture = fixture();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the valid fixture must authorize");
    let other = Dispatcher::new(
        AllowAll {
            bundle: fixture.dispatcher.config.policy_bundle.clone(),
            policy_digest: fixture.dispatcher.config.policy_digest.clone(),
            fault: None,
        },
        TestPort::new(fixture.dispatcher.adapter.clone(), "effect-port:fs"),
        fixture.dispatcher.ledger.clone(),
        DispatcherConfig::new(
            fixture.dispatcher.config.policy_bundle.clone(),
            fixture.dispatcher.config.policy_digest.clone(),
            fixture.dispatcher.config.runtime.clone(),
            fixture.dispatcher.config.replay_domain.clone(),
            fixture.dispatcher.config.max_lease_ttl,
            fixture.intent.delegation_chain.clone(),
            [fixture.intent.operation.clone()],
        )
        .expect("the second dispatcher configuration must be valid"),
    );

    let result = other.execute(&lease).await;
    assert!(
        result.is_ok(),
        "a dispatcher sharing the durable ledger and exact configuration may claim the lease"
    );
    assert_eq!(
        other.port.call_count(),
        1,
        "handoff must invoke only the registered target port"
    );
    let replay = fixture.dispatcher.execute(&lease).await;
    assert!(
        matches!(replay, Err(RuntimeError::ReplayDetected { .. })),
        "the original dispatcher must observe the shared claim as replay"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the sibling-budget fixture must construct and reserve its valid baseline"
)]
async fn sibling_reservations_share_the_parent_budget_and_pending_expiry_releases_it() {
    let now = fixed_now();
    let authority = PrincipalId::new();
    let parent_budget = ResourceBudget {
        wall_ms: Some(1_500),
        cpu_ms: Some(0),
        memory_bytes: Some(2 * 1024 * 1024),
        io_bytes: Some(0),
        network_bytes: Some(0),
        external_cost_microunits: Some(0),
    };
    let root = delegation(
        authority,
        now + SignedDuration::from_hours(1),
        parent_budget,
    );
    let first_principal = PrincipalId::new();
    let second_principal = PrincipalId::new();
    let first_child = child_delegation(&root, first_principal.clone(), budget());
    let second_child = child_delegation(&root, second_principal.clone(), budget());
    let operation = read_operation();
    let first = OperationIntent {
        principal: first_principal,
        delegation_chain: vec![root.clone(), first_child.clone()],
        operation: operation.clone(),
        resources: BTreeSet::from(["repo:main".to_string()]),
        budget: budget(),
        idempotency_key: None,
        execution: None,
    };
    let second = OperationIntent {
        principal: second_principal,
        delegation_chain: vec![root.clone(), second_child.clone()],
        operation: operation.clone(),
        resources: BTreeSet::from(["repo:main".to_string()]),
        budget: budget(),
        idempotency_key: None,
        execution: None,
    };
    let policy_bundle = PolicyBundleId::new();
    let policy_digest = Digest::blake3(b"sibling-budget-policy");
    let ledger = InMemoryAuthorizationLedger::at(now);
    let dispatcher = Dispatcher::new(
        AllowAll {
            bundle: policy_bundle.clone(),
            policy_digest: policy_digest.clone(),
            fault: None,
        },
        TestPort::new(AdapterId::new(), "effect-port:fs"),
        ledger.clone(),
        DispatcherConfig::new(
            policy_bundle,
            policy_digest,
            RuntimeGenerationId::derive(b"shared parent budget generation"),
            "shared-parent-budget".to_string(),
            SignedDuration::from_mins(5),
            [root, first_child, second_child],
            [operation],
        )
        .expect("the sibling delegation registry must be valid"),
    );

    let _first_lease = dispatcher
        .authorize(&first)
        .await
        .expect("the first child must reserve within the parent budget");
    let oversubscribed = dispatcher.authorize(&second).await;
    assert!(
        matches!(oversubscribed, Err(RuntimeError::BudgetUnavailable { .. })),
        "sibling reservations must not each spend the parent's full capacity"
    );

    ledger
        .set_observed_at(now + SignedDuration::from_mins(6))
        .await;
    assert!(
        dispatcher.authorize(&second).await.is_ok(),
        "an expired unclaimed reservation must release its held budget"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "idempotency retention starts from one valid reserved and claimed lease"
)]
async fn idempotency_key_survives_dispatcher_recreation_on_the_shared_ledger() {
    let mut fixture = fixture();
    fixture.intent.operation.requires_idempotency = true;
    fixture.intent.idempotency_key = Some("stable-request-42".to_string());
    fixture.dispatcher.config.trusted_operations.insert(
        fixture.intent.operation.id.clone(),
        fixture.intent.operation.clone(),
    );
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the first idempotent request must reserve");
    assert!(
        matches!(
            fixture.dispatcher.authorize(&fixture.intent).await,
            Err(RuntimeError::ReplayDetected { .. })
        ),
        "a duplicate pending idempotency key must fail before another lease is returned"
    );
    fixture
        .dispatcher
        .execute(&lease)
        .await
        .expect("the reserved idempotent request must execute once");

    let replacement = Dispatcher::new(
        AllowAll {
            bundle: fixture.dispatcher.config.policy_bundle.clone(),
            policy_digest: fixture.dispatcher.config.policy_digest.clone(),
            fault: None,
        },
        TestPort::new(fixture.dispatcher.adapter.clone(), "effect-port:fs"),
        fixture.dispatcher.ledger.clone(),
        DispatcherConfig::new(
            fixture.dispatcher.config.policy_bundle.clone(),
            fixture.dispatcher.config.policy_digest.clone(),
            fixture.dispatcher.config.runtime.clone(),
            fixture.dispatcher.config.replay_domain.clone(),
            fixture.dispatcher.config.max_lease_ttl,
            fixture.intent.delegation_chain.clone(),
            [fixture.intent.operation.clone()],
        )
        .expect("the replacement dispatcher configuration must be equivalent"),
    );
    assert!(
        matches!(
            replacement.authorize(&fixture.intent).await,
            Err(RuntimeError::ReplayDetected { .. })
        ),
        "a recreated dispatcher must observe the retained semantic replay key"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the isolated-ledger test begins with one valid reservation"
)]
async fn an_unrelated_ledger_cannot_claim_a_lease() {
    let fixture = fixture();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the source dispatcher must reserve the lease");
    let isolated = Dispatcher::new(
        AllowAll {
            bundle: fixture.dispatcher.config.policy_bundle.clone(),
            policy_digest: fixture.dispatcher.config.policy_digest.clone(),
            fault: None,
        },
        TestPort::new(fixture.dispatcher.adapter.clone(), "effect-port:fs"),
        InMemoryAuthorizationLedger::at(fixture.now),
        DispatcherConfig::new(
            fixture.dispatcher.config.policy_bundle.clone(),
            fixture.dispatcher.config.policy_digest.clone(),
            fixture.dispatcher.config.runtime.clone(),
            fixture.dispatcher.config.replay_domain.clone(),
            fixture.dispatcher.config.max_lease_ttl,
            fixture.intent.delegation_chain.clone(),
            [fixture.intent.operation.clone()],
        )
        .expect("the isolated dispatcher configuration must be equivalent"),
    );

    assert!(
        matches!(
            isolated.execute(&lease).await,
            Err(RuntimeError::ReservationMismatch { .. })
        ),
        "an equivalent process without the durable reservation must fail closed"
    );
    assert_eq!(
        isolated.port.call_count(),
        0,
        "an unreserved lease must not reach the isolated port"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the failure-accounting test needs one valid reservation before the port error"
)]
async fn port_failure_keeps_replay_and_full_budget_conservatively_spent() {
    let mut fixture = fixture();
    let exact_limit = fixture.intent.budget.clone();
    let root = fixture
        .intent
        .delegation_chain
        .first_mut()
        .expect("the fixture must contain one trusted root");
    root.budget = exact_limit;
    fixture
        .dispatcher
        .config
        .trusted_delegations
        .insert(root.id.clone(), root.clone());
    fixture.dispatcher.port.fail = true;
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the only available budget must reserve");
    assert!(
        matches!(
            fixture.dispatcher.execute(&lease).await,
            Err(RuntimeError::EffectInvocation { .. })
        ),
        "the port's source failure must remain distinct from authorization failure"
    );
    assert!(
        matches!(
            fixture.dispatcher.authorize(&fixture.intent).await,
            Err(RuntimeError::BudgetUnavailable { .. })
        ),
        "an indeterminate effect must keep the full reserved maximum charged"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "axis tampering starts from valid typed claims"
)]
async fn every_bound_axis_rejects_substitution() {
    let fixture = fixture();

    assert_tampering_rejected(&fixture, "lease identity", |claims| {
        claims.id = EffectLeaseId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "reservation identity", |claims| {
        claims.reservation_id = BudgetReservationId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "principal", |claims| {
        claims.principal = PrincipalId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "delegation chain", |claims| {
        claims
            .delegation_chain
            .first_mut()
            .expect("the fixture lease must contain one delegation")
            .id = DelegationId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "operation", |claims| {
        claims.operation.id = OperationId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "resources", |claims| {
        claims.resources.insert("repo:other".to_string());
    })
    .await;
    assert_tampering_rejected(&fixture, "effects", |claims| {
        claims.operation.effects.insert(Effect::WriteFilesystem);
    })
    .await;
    assert_tampering_rejected(&fixture, "data classes", |claims| {
        claims
            .operation
            .data_classes
            .insert(DataClass::Confidential);
    })
    .await;
    assert_tampering_rejected(&fixture, "budget", |claims| {
        claims.budget.wall_ms = Some(2000);
    })
    .await;
    assert_tampering_rejected(&fixture, "policy bundle", |claims| {
        claims.decision.bundle = PolicyBundleId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "policy digest", |claims| {
        claims.decision.policy_digest = Digest::blake3(b"different-policy");
    })
    .await;
    assert_tampering_rejected(&fixture, "runtime generation", |claims| {
        claims.runtime = RuntimeGenerationId::derive(b"different runtime generation");
    })
    .await;
    assert_tampering_rejected(&fixture, "adapter", |claims| {
        claims.adapter = AdapterId::new();
    })
    .await;
    assert_tampering_rejected(&fixture, "audience", |claims| {
        claims.audience.insert("effect-port:network".to_string());
    })
    .await;
    assert_tampering_rejected(&fixture, "expiry", |claims| {
        claims.expires_at += SignedDuration::from_hours(1);
    })
    .await;
    assert_tampering_rejected(&fixture, "replay domain", |claims| {
        claims.replay_domain = "other-runtime".to_string();
    })
    .await;
}
