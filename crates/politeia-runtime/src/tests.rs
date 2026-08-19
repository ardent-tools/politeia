use std::sync::atomic::{AtomicUsize, Ordering};

use jiff::SignedDuration;
use politeia_core::{DataClass, DelegationId, OperationId, ResourceBudget};

use super::*;

#[derive(Debug)]
struct TestError;

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("synthetic fixture failure")
    }
}

impl std::error::Error for TestError {}

struct AllowAll {
    bundle: PolicyBundleId,
    policy_digest: Digest,
    fault: Option<DecisionFault>,
}

#[derive(Clone, Copy)]
enum DecisionFault {
    Principal,
    Bundle,
    PolicyDigest,
    IntentDigest,
    Deny,
}

impl PolicyDecisionPoint for AllowAll {
    type Error = TestError;

    #[expect(
        clippy::expect_used,
        reason = "the typed in-memory fixture is required to encode"
    )]
    fn decide(
        &self,
        intent: &OperationIntent,
    ) -> impl Future<Output = Result<PolicyDecision, Self::Error>> + Send {
        let intent_digest = intent
            .digest()
            .expect("the typed fixture intent must always encode");
        let mut decision = PolicyDecision {
            bundle: self.bundle.clone(),
            policy_digest: self.policy_digest.clone(),
            intent_digest,
            principal: intent.principal.clone(),
            allowed: true,
            binding_ids: vec!["fixture.allow".to_string()],
            reasons: vec!["synthetic fixture policy".to_string()],
        };
        match self.fault {
            Some(DecisionFault::Principal) => decision.principal = PrincipalId::new(),
            Some(DecisionFault::Bundle) => decision.bundle = PolicyBundleId::new(),
            Some(DecisionFault::PolicyDigest) => {
                decision.policy_digest = Digest::blake3(b"wrong policy")
            }
            Some(DecisionFault::IntentDigest) => {
                decision.intent_digest = Digest::blake3(b"wrong intent")
            }
            Some(DecisionFault::Deny) => decision.allowed = false,
            None => {}
        }
        std::future::ready(Ok(decision))
    }
}

struct TestPort {
    adapter: AdapterId,
    audience: String,
    calls: AtomicUsize,
    fail: bool,
}

impl TestPort {
    fn new(adapter: AdapterId, audience: &str) -> Self {
        Self {
            adapter,
            audience: audience.to_string(),
            calls: AtomicUsize::new(0),
            fail: false,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl EffectPort for TestPort {
    type Output = (EffectLeaseId, OperationId);
    type Error = TestError;

    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn execute<'lease>(
        &'lease self,
        invocation: AuthorizedEffect<'lease>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'lease {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = if self.fail {
            Err(TestError)
        } else {
            Ok((
                invocation.lease().id().clone(),
                invocation.lease().operation().id.clone(),
            ))
        };
        std::future::ready(result)
    }
}

struct UnavailableLedger;

impl AuthorizationLedger for UnavailableLedger {
    fn observed_at(&self) -> impl Future<Output = Result<Timestamp, RuntimeError>> + Send {
        std::future::ready(Err(RuntimeError::AuthorizationState {
            source: Box::new(TestError),
        }))
    }

    fn reserve(
        &self,
        _request: &ReservationRequest,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send {
        std::future::ready(Err(RuntimeError::AuthorizationState {
            source: Box::new(TestError),
        }))
    }

    fn claim(
        &self,
        _request: &ReservationRequest,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send {
        std::future::ready(Err(RuntimeError::AuthorizationState {
            source: Box::new(TestError),
        }))
    }
}

struct Fixture {
    dispatcher: Dispatcher<AllowAll, TestPort, InMemoryAuthorizationLedger>,
    intent: OperationIntent,
    now: Timestamp,
}

#[expect(
    clippy::expect_used,
    reason = "the fixed RFC 3339 fixture is a compile-time test invariant"
)]
fn fixed_now() -> Timestamp {
    "2026-08-19T12:00:00Z"
        .parse()
        .expect("the fixed test instant must parse")
}

fn delegation(principal: PrincipalId, expires_at: Timestamp, budget: ResourceBudget) -> Delegation {
    Delegation {
        id: DelegationId::new(),
        issuer: PrincipalId::new(),
        subject: principal,
        parent: None,
        actions: BTreeSet::from(["read".to_string()]),
        resources: BTreeSet::from(["repo:main".to_string()]),
        effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes: BTreeSet::from([DataClass::Public]),
        audience: BTreeSet::from(["effect-port:fs".to_string()]),
        expires_at,
        budget,
    }
}

fn child_delegation(
    parent: &Delegation,
    principal: PrincipalId,
    budget: ResourceBudget,
) -> Delegation {
    Delegation {
        id: DelegationId::new(),
        issuer: parent.subject.clone(),
        subject: principal,
        parent: Some(parent.id.clone()),
        actions: parent.actions.clone(),
        resources: parent.resources.clone(),
        effects: parent.effects.clone(),
        data_classes: parent.data_classes.clone(),
        audience: parent.audience.clone(),
        expires_at: parent.expires_at,
        budget,
    }
}

fn budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(1000),
        cpu_ms: Some(0),
        memory_bytes: Some(1024 * 1024),
        io_bytes: Some(0),
        network_bytes: Some(0),
        external_cost_microunits: Some(0),
    }
}

fn delegated_budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(100_000),
        cpu_ms: Some(0),
        memory_bytes: Some(100 * 1024 * 1024),
        io_bytes: Some(0),
        network_bytes: Some(0),
        external_cost_microunits: Some(0),
    }
}

fn read_operation() -> OperationSpec {
    OperationSpec {
        id: OperationId::new(),
        name: "read_repo".to_string(),
        actions: BTreeSet::from(["read".to_string()]),
        effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes: BTreeSet::from([DataClass::Public]),
        evidence_obligations: vec![],
        retryable: true,
        requires_idempotency: false,
    }
}

#[expect(
    clippy::expect_used,
    reason = "fixture construction must fail loudly if its trusted inputs drift"
)]
fn fixture() -> Fixture {
    let now = fixed_now();
    let principal = PrincipalId::new();
    let policy_bundle = PolicyBundleId::new();
    let policy_digest = Digest::blake3(b"fixture-policy");
    let adapter = AdapterId::new();
    let intent = OperationIntent {
        principal: principal.clone(),
        delegation_chain: vec![delegation(
            principal,
            now + SignedDuration::from_hours(1),
            delegated_budget(),
        )],
        operation: read_operation(),
        resources: BTreeSet::from(["repo:main".to_string()]),
        budget: budget(),
        idempotency_key: None,
    };
    let trusted_root = intent
        .delegation_chain
        .first()
        .expect("the fixture must contain one trusted root")
        .clone();
    let config = DispatcherConfig::new(
        policy_bundle.clone(),
        policy_digest.clone(),
        RuntimeGenerationId::new(),
        "test-runtime".to_string(),
        SignedDuration::from_hours(1),
        [trusted_root],
        [intent.operation.clone()],
    )
    .expect("the fixture dispatcher configuration must be valid");
    let dispatcher = Dispatcher::new(
        AllowAll {
            bundle: policy_bundle.clone(),
            policy_digest,
            fault: None,
        },
        TestPort::new(adapter, "effect-port:fs"),
        InMemoryAuthorizationLedger::at(now),
        config,
    );
    Fixture {
        dispatcher,
        intent,
        now,
    }
}

#[expect(
    clippy::expect_used,
    reason = "tampering tests require a valid baseline lease before mutation"
)]
async fn assert_tampering_rejected(
    fixture: &Fixture,
    description: &str,
    mutate: impl FnOnce(&mut LeaseClaims),
) {
    let mut lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the untampered fixture must authorize");
    mutate(&mut lease.claims);

    let result = fixture.dispatcher.execute(&lease).await;
    assert!(
        matches!(result, Err(RuntimeError::LeaseMismatch { .. })),
        "tampering with {description} must fail before effect invocation"
    );
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        0,
        "tampering with {description} must not reach the effect port"
    );
}

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

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "the valid fixture must authorize and execute before assertions"
)]
async fn valid_lease_executes_exactly_once() {
    let fixture = fixture();
    let lease = fixture
        .dispatcher
        .authorize(&fixture.intent)
        .await
        .expect("the valid fixture must authorize");

    let (executed_lease, executed_operation) = fixture
        .dispatcher
        .execute(&lease)
        .await
        .expect("the valid lease must execute");
    assert_eq!(
        executed_lease,
        lease.id().clone(),
        "the port must receive the exact authorized lease"
    );
    assert_eq!(
        executed_operation,
        fixture.intent.operation.id.clone(),
        "the port must receive the exact authorized operation"
    );
    assert_eq!(
        fixture.dispatcher.port.call_count(),
        1,
        "one valid execution must invoke the port once"
    );
}

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
    };
    let second = OperationIntent {
        principal: second_principal,
        delegation_chain: vec![root.clone(), second_child.clone()],
        operation: operation.clone(),
        resources: BTreeSet::from(["repo:main".to_string()]),
        budget: budget(),
        idempotency_key: None,
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
            RuntimeGenerationId::new(),
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
        claims.runtime = RuntimeGenerationId::new();
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

#[test]
#[expect(
    clippy::expect_used,
    reason = "wire tests fail loudly when valid fixture serialization changes"
)]
fn operation_intent_wire_format_is_fail_closed() {
    let fixture = fixture();
    let encoded =
        serde_json::to_value(&fixture.intent).expect("the typed operation intent must serialize");
    let decoded: OperationIntent = serde_json::from_value(encoded.clone())
        .expect("the typed operation intent must deserialize");
    assert_eq!(
        decoded.operation, fixture.intent.operation,
        "the operation contract must round-trip through its wire form"
    );
    assert_eq!(
        decoded.delegation_chain, fixture.intent.delegation_chain,
        "the delegation chain must round-trip through its wire form"
    );

    let mut object = encoded
        .as_object()
        .expect("an operation intent must serialize as an object")
        .clone();
    object.insert("unexpected".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<OperationIntent>(serde_json::Value::Object(object));
    assert!(
        result.is_err(),
        "unknown operation-intent fields must fail closed"
    );
}
