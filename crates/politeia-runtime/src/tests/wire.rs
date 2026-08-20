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
