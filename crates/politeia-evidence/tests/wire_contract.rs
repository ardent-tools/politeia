use std::any::type_name;

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::trust::{
    AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey,
};
use politeia_core::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId, ResourceBudget, RuntimeGenerationId,
};
use politeia_evidence::authority::{AuthorityContext, institution_audience};
use politeia_evidence::{
    Attestation, DelegatedVerification, VERIFY_ASSURANCE_ACTION, Verification,
    assurance_subject_resource,
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
#[expect(
    clippy::expect_used,
    reason = "wire fixture timestamp must fail immediately if malformed"
)]
fn verification_rejects_unknown_fields() {
    assert_closed_record(&Verification {
        subject: Digest::blake3(b"verified subject"),
        evidence: vec![EvidenceId::new()],
        passed: true,
        verified_at: "2026-08-21T00:00:00Z"
            .parse()
            .expect("fixture timestamp is valid"),
    });
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn attestation_rejects_unknown_fields() {
    let institution = InstitutionId::new();
    let workspace = InstitutionWorkspaceId::new();
    let owner = PrincipalId::new();
    let verifier = PrincipalId::new();
    let actor = PrincipalId::new();
    let owner_key = SigningKey::from_bytes(&[7; 32]);
    let verifier_key = SigningKey::from_bytes(&[8; 32]);
    let permissions = BTreeSet::from([AdmissionKind::Delegation, AdmissionKind::Verification]);
    let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
        institution.clone(),
        workspace.clone(),
        [
            TrustedSigningKey::new(
                owner.clone(),
                owner_key.verifying_key().to_bytes(),
                permissions.clone(),
            )
            .expect("owner key is valid"),
            TrustedSigningKey::new(
                verifier.clone(),
                verifier_key.verifying_key().to_bytes(),
                permissions,
            )
            .expect("verifier key is valid"),
        ],
    )
    .expect("fixture principals are unique");
    let now: Timestamp = "2026-08-21T00:00:00Z"
        .parse()
        .expect("fixture timestamp is valid");
    let verification = Verification {
        subject: Digest::blake3(b"attested subject"),
        evidence: vec![EvidenceId::new()],
        passed: true,
        verified_at: now,
    };
    let resource = assurance_subject_resource(&verification.subject)
        .expect("fixture subject has a canonical token");
    let verification_wire = SignedAdmissionWire::sign(
        AdmissionKind::Verification,
        institution.clone(),
        workspace.clone(),
        verifier.clone(),
        verification,
        &verifier_key,
    )
    .expect("verification encodes");
    let verification = anchors
        .admit_expected(AdmissionKind::Verification, verification_wire)
        .expect("verification signature is valid");
    let delegation = Delegation {
        id: DelegationId::new(),
        issuer: owner.clone(),
        subject: verifier,
        parent: None,
        actions: BTreeSet::from([VERIFY_ASSURANCE_ACTION.to_string()]),
        resources: BTreeSet::from([resource]),
        effects: BTreeSet::<Effect>::new(),
        data_classes: BTreeSet::<DataClass>::new(),
        audience: BTreeSet::from([institution_audience(&institution)]),
        expires_at: now + SignedDuration::from_hours(1),
        budget: ResourceBudget {
            wall_ms: Some(0),
            cpu_ms: Some(0),
            memory_bytes: Some(0),
            io_bytes: Some(0),
            network_bytes: Some(0),
            external_cost_microunits: Some(0),
        },
    };
    let delegation_wire = SignedAdmissionWire::sign(
        AdmissionKind::Delegation,
        institution.clone(),
        workspace.clone(),
        owner.clone(),
        delegation,
        &owner_key,
    )
    .expect("delegation encodes");
    let delegation = anchors
        .admit_expected(AdmissionKind::Delegation, delegation_wire)
        .expect("delegation signature is valid");
    let context = AuthorityContext::new(institution, workspace, owner, now);
    let verification = DelegatedVerification::admit(&verification, &delegation, &context)
        .expect("verification has exact authority");
    let attestation = Attestation::issue(
        &verification,
        &actor,
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"runtime generation"),
        AdapterId::new(),
        DelegationId::new(),
    )
    .expect("an independent passing verification may be attested");
    assert_closed_record(&attestation);
}
