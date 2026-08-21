use std::any::type_name;

use politeia_core::PrincipalId;
use politeia_policy::hardening::{BindingAuthority, HardeningLadder, HardeningState};
use politeia_policy::{
    ClauseKind, Consequence, DetectorSpec, EvidenceClass, NormativeClause, PolicyBinding, Waiver,
};
use schemars::{JsonSchema, schema_for};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

#[expect(
    clippy::expect_used,
    reason = "wire-contract fixtures require canonical JSON objects and schemas"
)]
fn assert_closed_record<T>(value: &T)
where
    T: DeserializeOwned + JsonSchema + Serialize,
{
    let mut canonical = serde_json::to_value(value).expect("fixture must serialize to JSON");
    assert!(
        serde_json::from_value::<T>(canonical.clone()).is_ok(),
        "canonical {} JSON must deserialize",
        type_name::<T>()
    );

    canonical
        .as_object_mut()
        .expect("record fixture must serialize as an object")
        .insert("ambient_authority".to_string(), Value::Bool(true));
    assert!(
        serde_json::from_value::<T>(canonical).is_err(),
        "{} must reject unknown root fields",
        type_name::<T>()
    );

    let schema = serde_json::to_value(schema_for!(T)).expect("record schema must serialize");
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "{} schema must close the root object",
        type_name::<T>()
    );
}

#[test]
fn normative_clause_rejects_unknown_fields() {
    assert_closed_record(&NormativeClause {
        id: "clause:approved-change".to_string(),
        kind: ClauseKind::Precondition,
        statement: "the institution owner approved the change".to_string(),
    });
}

#[test]
fn detector_spec_rejects_unknown_fields() {
    assert_closed_record(&DetectorSpec {
        id: "detector:approval-receipt".to_string(),
        evidence_class: EvidenceClass::Substance,
        known_blind_spots: vec!["revocation after observation".to_string()],
        adversarially_calibrated: true,
    });
}

#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot climb its own ladder is a broken test"
)]
fn enforcing_authority() -> BindingAuthority {
    let mut ladder = HardeningLadder::new();
    for rung in [
        HardeningState::Observed,
        HardeningState::Proposed,
        HardeningState::Approved,
        HardeningState::Shadow,
        HardeningState::Calibrated,
        HardeningState::Advisory,
        HardeningState::Enforced,
    ] {
        ladder.advance(rung).expect("the full climb is legal");
    }
    BindingAuthority::new(ladder, Consequence::Deny).expect("an enforced binding may deny")
}

#[test]
fn policy_binding_rejects_unknown_fields() {
    assert_closed_record(&PolicyBinding {
        id: "binding:approved-change".to_string(),
        clause_id: "clause:approved-change".to_string(),
        detector_ids: vec!["detector:approval-receipt".to_string()],
        scope: "institution:production".to_string(),
        authority: enforcing_authority(),
    });
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot serialize is a broken test, not a finding"
)]
fn a_binding_cannot_arrive_at_enforcement_off_the_wire() {
    // The wire is where an unearned rung would enter. `assert_closed_record`
    // proves the record refuses unknown fields; this proves it refuses a known
    // field carrying an unearned claim, which no closure test can see.
    let mut canonical = serde_json::to_value(PolicyBinding {
        id: "binding:approved-change".to_string(),
        clause_id: "clause:approved-change".to_string(),
        detector_ids: vec!["detector:approval-receipt".to_string()],
        scope: "institution:production".to_string(),
        authority: enforcing_authority(),
    })
    .expect("fixture must serialize to JSON");

    canonical["authority"]["hardening"] = serde_json::json!(["unknown", "enforced"]);
    assert!(
        serde_json::from_value::<PolicyBinding>(canonical).is_err(),
        "a binding that never shadowed or calibrated must not deserialize as enforcing"
    );
}

#[test]
fn waiver_rejects_unknown_fields() {
    assert_closed_record(&Waiver {
        id: "waiver:maintenance-window".to_string(),
        binding_id: "binding:approved-change".to_string(),
        scope: "institution:maintenance".to_string(),
        reason: "owner-approved maintenance".to_string(),
        issuer: PrincipalId::new(),
        expires_at_rfc3339: "2026-08-21T00:00:00Z".to_string(),
    });
}
