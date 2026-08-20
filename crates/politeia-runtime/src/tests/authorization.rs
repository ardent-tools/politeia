#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the fixed fixture always contains its registered root"
)]
async fn expired_delegation_fails_closed() {
    let mut fixture = fixture();
    let root = fixture
        .intent
        .delegation_chain
        .first_mut()
        .expect("the fixture must contain one delegation");
    root.expires_at = fixture.now - SignedDuration::from_hours(1);
    fixture
        .dispatcher
        .config
        .trusted_delegations
        .insert(root.id.clone(), root.clone());
    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(
        matches!(result, Err(RuntimeError::InvalidDelegation { .. })),
        "an expired delegation must fail closed"
    );
}
#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the forged-child test starts from the fixture's admitted root"
)]
async fn unregistered_child_delegation_cannot_claim_issuer_authority() {
    let mut fixture = fixture();
    let root = fixture
        .intent
        .delegation_chain
        .first()
        .expect("the fixture must contain one trusted root")
        .clone();
    let attacker = PrincipalId::new();
    fixture.intent.principal = attacker.clone();
    fixture.intent.delegation_chain.push(child_delegation(
        &root,
        attacker,
        fixture.intent.budget.clone(),
    ));

    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(
        matches!(result, Err(RuntimeError::InvalidDelegation { .. })),
        "an unsigned child absent from the trusted registry must fail closed"
    );
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        0,
        "forged delegated authority must not reach the effect port"
    );
}

#[tokio::test]
async fn caller_cannot_weaken_the_registered_operation_contract() {
    let mut fixture = fixture();
    fixture.intent.operation.requires_idempotency = true;
    fixture.intent.idempotency_key = Some("caller-selected-contract".to_string());

    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(
        matches!(result, Err(RuntimeError::InvalidDelegation { .. })),
        "a caller-supplied operation variant must not replace the registered contract"
    );
}

#[test]
fn retryable_productive_operation_requires_idempotency() {
    let fixture = fixture();
    let mut operation = fixture.intent.operation.clone();
    operation.effects.insert(Effect::WriteExternalSystem);

    let result = DispatcherConfig::new(
        fixture.dispatcher.config.policy_bundle.clone(),
        fixture.dispatcher.config.policy_digest.clone(),
        fixture.dispatcher.config.runtime.clone(),
        fixture.dispatcher.config.replay_domain.clone(),
        fixture.dispatcher.config.max_lease_ttl,
        fixture.intent.delegation_chain.clone(),
        [operation],
    );
    assert!(
        matches!(result, Err(RuntimeError::InvalidConfiguration { .. })),
        "retryable productive effects must require semantic idempotency"
    );
}

#[tokio::test]
async fn operation_budget_must_be_finite_before_policy_or_reservation() {
    let mut fixture = fixture();
    fixture.intent.budget.cpu_ms = None;

    let result = fixture.dispatcher.authorize(&fixture.intent).await;
    assert!(
        matches!(result, Err(RuntimeError::InvalidDelegation { .. })),
        "an invocation with an unbounded resource axis cannot be reserved"
    );
}

#[tokio::test]
async fn mismatched_or_denied_policy_receipts_fail_before_lease_minting() {
    for fault in [
        DecisionFault::Principal,
        DecisionFault::Bundle,
        DecisionFault::PolicyDigest,
        DecisionFault::IntentDigest,
        DecisionFault::Deny,
    ] {
        let mut fixture = fixture();
        fixture.dispatcher.policy.fault = Some(fault);

        let result = fixture.dispatcher.authorize(&fixture.intent).await;
        assert!(
            matches!(
                result,
                Err(RuntimeError::DecisionMismatch { .. } | RuntimeError::Denied { .. })
            ),
            "a policy receipt that is denied or not exact must fail closed"
        );
        assert_eq!(
            fixture.dispatcher.port.call_count(),
            0,
            "a rejected policy receipt must not reach the effect port"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the unavailable-ledger fixture reuses one exact trusted configuration"
)]
async fn unavailable_authorization_state_fails_closed() {
    let fixture = fixture();
    let dispatcher = Dispatcher::new(
        AllowAll {
            bundle: fixture.dispatcher.config.policy_bundle.clone(),
            policy_digest: fixture.dispatcher.config.policy_digest.clone(),
            fault: None,
        },
        TestPort::new(fixture.dispatcher.adapter.clone(), "effect-port:fs"),
        UnavailableLedger,
        DispatcherConfig::new(
            fixture.dispatcher.config.policy_bundle.clone(),
            fixture.dispatcher.config.policy_digest.clone(),
            fixture.dispatcher.config.runtime.clone(),
            fixture.dispatcher.config.replay_domain.clone(),
            fixture.dispatcher.config.max_lease_ttl,
            fixture.intent.delegation_chain.clone(),
            [fixture.intent.operation.clone()],
        )
        .expect("the unavailable-ledger dispatcher configuration must be valid"),
    );

    let result = dispatcher.authorize(&fixture.intent).await;
    assert!(
        matches!(result, Err(RuntimeError::AuthorizationState { .. })),
        "a ledger clock failure must reject authorization without a lease"
    );
    assert_eq!(
        dispatcher.port.call_count(),
        0,
        "unavailable authorization state must not reach the effect port"
    );
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the binding test inspects a deliberately complete valid fixture"
)]
async fn lease_binds_every_kernel_contract_axis() {
    let fixture = fixture();
    let delegation = fixture
        .intent
        .delegation_chain
        .first()
        .expect("the fixture must contain one delegation");
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("valid delegation authorizes");
    let expected_chain = fixture.intent.delegation_chain.clone();

    let reservation = lease
        .reservation_request()
        .expect("the lease reservation must derive from typed claims");
    assert_eq!(
        reservation.reservation_id(),
        lease.reservation_id(),
        "the lease must bind its durable reservation identity"
    );
    assert_eq!(
        lease.principal(),
        &fixture.intent.principal,
        "the lease must bind the requesting principal"
    );
    assert_eq!(
        lease.delegation_chain(),
        expected_chain.as_slice(),
        "the lease must bind the exact delegation chain"
    );
    assert_eq!(
        lease.operation(),
        &fixture.intent.operation,
        "the lease must bind the exact operation contract"
    );
    assert_eq!(
        lease.resources(),
        &fixture.intent.resources,
        "the lease must bind the exact resource set"
    );
    assert_eq!(
        lease.effects(),
        &fixture.intent.operation.effects,
        "the lease must bind the exact effect set"
    );
    assert_eq!(
        lease.data_classes(),
        &fixture.intent.operation.data_classes,
        "the lease must bind the exact data classes"
    );
    assert_eq!(
        lease.budget(),
        &fixture.intent.budget,
        "the lease must bind the requested bounded budget"
    );
    assert_eq!(
        lease.policy(),
        &fixture.dispatcher.config.policy_bundle,
        "the lease must bind the policy bundle identity"
    );
    assert_eq!(
        lease.policy_digest(),
        &fixture.dispatcher.config.policy_digest,
        "the lease must bind the exact policy digest"
    );
    assert_eq!(
        lease.runtime(),
        &fixture.dispatcher.config.runtime,
        "the lease must bind the runtime generation"
    );
    assert_eq!(
        lease.adapter(),
        &fixture.dispatcher.adapter,
        "the lease must bind the adapter identity"
    );
    assert_eq!(
        lease.audience(),
        &delegation.audience,
        "the lease must bind the delegated audience"
    );
    assert_eq!(
        lease.expires_at(),
        delegation.expires_at,
        "the lease must retain the delegation expiry"
    );
    assert_eq!(
        lease.replay_domain(),
        "test-runtime",
        "the lease must bind the dispatcher's replay domain"
    );
    assert!(
        lease
            .has_valid_claims_digest()
            .expect("typed fixture claims must encode"),
        "the lease must bind its immutable claims digest"
    );
}
