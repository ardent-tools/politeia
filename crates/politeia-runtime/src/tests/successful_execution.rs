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
