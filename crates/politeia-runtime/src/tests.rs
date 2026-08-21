use std::sync::atomic::{AtomicUsize, Ordering};

use jiff::SignedDuration;
use politeia_core::{
    CapabilityProfileId, CapabilityVerificationId, DataClass, DelegationId, EvidenceId,
    ExecutionResourceId, OperationId, ResourceBudget, RoutingDecisionId,
    institution::TrustDomainId,
};

use super::routing::{
    AvailabilitySnapshot, CapabilityProfile, CapabilityVerificationRecord, ExecutionLocality,
    ExecutionRequirement, ExecutionResource, ExecutionResourceDescriptor, Router, RoutingOutcome,
    SoftPreference,
};
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
                decision.policy_digest = Digest::blake3(b"wrong policy");
            }
            Some(DecisionFault::IntentDigest) => {
                decision.intent_digest = Digest::blake3(b"wrong intent");
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
        execution_requirement: None,
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
        execution: None,
    };
    let trusted_root = intent
        .delegation_chain
        .first()
        .expect("the fixture must contain one trusted root")
        .clone();
    let config = DispatcherConfig::new(
        policy_bundle.clone(),
        policy_digest.clone(),
        RuntimeGenerationId::derive(b"fixture runtime generation"),
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

include!("tests/authorization.rs");
include!("tests/successful_execution.rs");
include!("tests/routing_binding.rs");
include!("tests/replay.rs");
include!("tests/wire.rs");
include!("tests/authority_binding.rs");
