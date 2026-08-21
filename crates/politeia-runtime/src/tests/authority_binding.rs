// Every leaf-binding and registry check, exercised against the guard it names.
//
// Two gaps motivate this file. The registry-build attenuation check in
// `DispatcherConfig::new` had no test of any kind, so a child that widened its
// parent could have been admitted into the trusted registry and nothing would
// have said so. And the five leaf-binding checks in `validate_intent` were
// unreachable from the existing fixtures, because the identity checks that run
// before them reject any intent whose operation or chain has been altered —
// mutating the intent to widen it produces "unknown operation", not the
// binding refusal one is trying to observe.
//
// So the fixture here narrows the delegation on *both* sides of the identity
// check at once, leaving the registry self-consistent and the operation
// genuinely outside what the delegation permits.
//
// Each assertion names the exact `reason` the guard reports rather than only
// its error variant. Matching the variant alone would pass when a different
// guard fired first, which is precisely the failure these tests exist to rule
// out.

/// Build a dispatcher whose trusted delegation genuinely fails to cover the
/// trusted operation, so `validate_intent`'s leaf-binding checks are reachable.
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot build is a broken harness, not a finding"
)]
fn binding_fixture(narrow: impl FnOnce(&mut Delegation)) -> Fixture {
    let now = fixed_now();
    let principal = PrincipalId::new();
    let policy_bundle = PolicyBundleId::new();
    let policy_digest = Digest::blake3(b"binding-policy");

    let mut root = delegation(
        principal.clone(),
        now + SignedDuration::from_hours(1),
        delegated_budget(),
    );
    narrow(&mut root);

    let intent = OperationIntent {
        principal,
        // The same delegation the registry trusts, so the identity checks pass
        // and the binding checks are what decide.
        delegation_chain: vec![root.clone()],
        operation: read_operation(),
        resources: BTreeSet::from(["repo:main".to_string()]),
        budget: budget(),
        idempotency_key: None,
        execution: None,
    };

    let config = DispatcherConfig::new(
        policy_bundle.clone(),
        policy_digest.clone(),
        RuntimeGenerationId::derive(b"binding runtime generation"),
        "test-runtime".to_string(),
        SignedDuration::from_hours(1),
        [root],
        [intent.operation.clone()],
    )
    .expect("a single-root registry must be valid however narrow the delegation is");

    let dispatcher = Dispatcher::new(
        AllowAll {
            bundle: policy_bundle,
            policy_digest,
            fault: None,
        },
        TestPort::new(AdapterId::new(), "effect-port:fs"),
        InMemoryAuthorizationLedger::at(now),
        config,
    );

    Fixture {
        dispatcher,
        intent,
        now,
    }
}

/// Assert the named guard refuses the intent, and that nothing reached the port.
async fn assert_binding_refused(expected_reason: &str, narrow: impl FnOnce(&mut Delegation)) {
    let fixture = binding_fixture(narrow);
    let result = fixture.dispatcher.authorize(&fixture.intent).await;

    match result {
        Err(RuntimeError::InvalidDelegation { reason, .. }) => assert_eq!(
            reason, expected_reason,
            "a delegation guard refused, but not the one under test"
        ),
        Err(other) => panic!("expected an invalid-delegation refusal, got {other:?}"),
        Ok(_) => panic!("authority exceeding the delegation was authorized: {expected_reason}"),
    }

    assert_eq!(
        fixture.dispatcher.port.call_count(),
        0,
        "a refused authorization must not reach the effect port"
    );
}

#[tokio::test]
async fn operation_actions_exceeding_the_delegation_are_refused() {
    assert_binding_refused("operation actions exceed the delegation", |root| {
        root.actions.clear();
    })
    .await;
}

#[tokio::test]
async fn intent_resources_exceeding_the_delegation_are_refused() {
    assert_binding_refused("operation resources exceed the delegation", |root| {
        root.resources.clear();
    })
    .await;
}

#[tokio::test]
async fn operation_effects_exceeding_the_delegation_are_refused() {
    assert_binding_refused("operation effects exceed the delegation", |root| {
        root.effects.clear();
    })
    .await;
}

#[tokio::test]
async fn operation_data_classes_exceeding_the_delegation_are_refused() {
    assert_binding_refused("operation data classes exceed the delegation", |root| {
        root.data_classes.clear();
    })
    .await;
}

#[tokio::test]
async fn a_requested_budget_exceeding_the_delegation_is_refused() {
    assert_binding_refused("requested budget exceeds the delegation", |root| {
        // One millisecond of wall clock, against an intent asking for a
        // thousand. Every other cap stays wide, so this is a single-axis
        // widening rather than a wholesale mismatch.
        root.budget.wall_ms = Some(1);
    })
    .await;
}

// --- The registry-build check ------------------------------------------------

/// Assert `DispatcherConfig::new` refuses a registry whose child widens its parent.
///
/// This guard walks the whole trusted registry root-to-leaf and had no test of
/// any kind. It is the earliest point a widened authority could enter the
/// system, and the only one that runs before any intent exists to be checked.
#[expect(
    clippy::expect_used,
    reason = "the parent side of the fixture must build for the child to widen it"
)]
fn assert_registry_refuses(axis: &str, widen: impl FnOnce(&mut Delegation)) {
    let now = fixed_now();
    let root = delegation(
        PrincipalId::new(),
        now + SignedDuration::from_hours(1),
        delegated_budget(),
    );
    let mut child = child_delegation(&root, PrincipalId::new(), delegated_budget());
    widen(&mut child);

    let result = DispatcherConfig::new(
        PolicyBundleId::new(),
        Digest::blake3(b"registry-policy"),
        RuntimeGenerationId::derive(b"registry runtime generation"),
        "test-runtime".to_string(),
        SignedDuration::from_hours(1),
        [root.clone(), child],
        [read_operation()],
    );

    assert!(
        matches!(result, Err(RuntimeError::InvalidConfiguration { .. })),
        "a registry child widening {axis} was admitted as trusted"
    );

    // Positive control in the same shape: without the widening, this registry
    // builds. Otherwise the assertion above would pass against a fixture that
    // was invalid for some unrelated reason.
    let faithful = child_delegation(&root, PrincipalId::new(), delegated_budget());
    DispatcherConfig::new(
        PolicyBundleId::new(),
        Digest::blake3(b"registry-policy"),
        RuntimeGenerationId::derive(b"registry runtime generation"),
        "test-runtime".to_string(),
        SignedDuration::from_hours(1),
        [root, faithful],
        [read_operation()],
    )
    .expect("an unwidened child must be admitted, or the refusal above proves nothing");
}

#[test]
fn a_registry_child_widening_actions_is_refused() {
    assert_registry_refuses("actions", |child| {
        child.actions.insert("write".to_string());
    });
}

#[test]
fn a_registry_child_widening_resources_is_refused() {
    assert_registry_refuses("resources", |child| {
        child.resources.insert("repo:secrets".to_string());
    });
}

#[test]
fn a_registry_child_widening_effects_is_refused() {
    assert_registry_refuses("effects", |child| {
        child.effects.insert(Effect::WriteExternalSystem);
    });
}

#[test]
fn a_registry_child_widening_data_classes_is_refused() {
    assert_registry_refuses("data classes", |child| {
        child.data_classes.insert(DataClass::Secret);
    });
}

#[test]
fn a_registry_child_widening_audience_is_refused() {
    assert_registry_refuses("audience", |child| {
        child.audience.insert("effect-port:net".to_string());
    });
}

#[test]
fn a_registry_child_outliving_its_parent_is_refused() {
    assert_registry_refuses("expiry", |child| {
        child.expires_at = child.expires_at + SignedDuration::from_secs(1);
    });
}

#[test]
fn a_registry_child_raising_a_budget_cap_is_refused() {
    assert_registry_refuses("a budget cap", |child| {
        child.budget.wall_ms = child.budget.wall_ms.map(|cap| cap.saturating_add(1));
    });
}

#[test]
fn a_registry_child_removing_a_budget_cap_is_refused() {
    // The other way to exceed a cap: not a larger number, the absence of one.
    assert_registry_refuses("a removed budget cap", |child| {
        child.budget.wall_ms = None;
    });
}
