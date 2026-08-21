use std::any::type_name;

use politeia_core::{
    AdapterId, DelegationId, Digest, EvidenceId, PolicyBundleId, PrincipalId, RuntimeGenerationId,
    evidence::IndependenceClass,
};
use politeia_evidence::{Attestation, Verification};
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
fn verification_rejects_unknown_fields() {
    assert_closed_record(&Verification {
        subject: Digest::blake3(b"verified subject"),
        verifier: PrincipalId::new(),
        evidence: vec![EvidenceId::new()],
        passed: true,
        independence: IndependenceClass::IndependentAgent,
    });
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn attestation_rejects_unknown_fields() {
    let verifier = PrincipalId::new();
    let verification = Verification {
        subject: Digest::blake3(b"attested subject"),
        verifier,
        evidence: vec![EvidenceId::new()],
        passed: true,
        independence: IndependenceClass::IndependentService,
    };
    let attestation = Attestation::issue(
        &verification,
        &PrincipalId::new(),
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"runtime generation"),
        AdapterId::new(),
        DelegationId::new(),
    )
    .expect("an independent passing verification may be attested");
    assert_closed_record(&attestation);
}
