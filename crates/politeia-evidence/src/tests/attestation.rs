#![expect(
    clippy::expect_used,
    reason = "attestation fixtures must fail immediately when admission invariants break"
)]

use politeia_core::trust::AdmissionKind;
use politeia_core::{
    AdapterId, DelegationId, Digest, EvidenceId, PolicyBundleId, RuntimeGenerationId,
};

use crate::authority::AuthorityRefusal;
use crate::test_support::TestAuthority;
use crate::{
    Attestation, AttestationRefusal, DelegatedVerification, VERIFY_ASSURANCE_ACTION, Verification,
    VerificationAdmissionRefusal, assurance_subject_resource,
};

fn verification(trust: &TestAuthority, passed: bool, evidence_count: usize) -> Verification {
    Verification {
        subject: Digest::blake3(b"the verified subject"),
        evidence: (0..evidence_count).map(|_| EvidenceId::new()).collect(),
        passed,
        verified_at: trust.now(),
    }
}

#[test]
fn independently_delegated_verification_may_be_attested() {
    let trust = TestAuthority::new();
    let verdict = verification(&trust, true, 1);
    let resource = assurance_subject_resource(&verdict.subject).expect("subject encodes");
    let admitted = trust.admit(AdmissionKind::Verification, &trust.verifier, verdict);
    let authority = trust.admit(
        AdmissionKind::Delegation,
        &trust.owner,
        trust.grant(trust.verifier.clone(), VERIFY_ASSURANCE_ACTION, resource),
    );
    let delegated = DelegatedVerification::admit(&admitted, &authority, &trust.context())
        .expect("verifier has exact subject authority");
    let attestation = Attestation::issue(
        &delegated,
        &trust.producer,
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"runtime generation"),
        AdapterId::new(),
        DelegationId::new(),
    )
    .expect("independent passing verification attests");
    assert!(
        attestation.covers(&Digest::blake3(b"the verified subject")),
        "attestation covers the exact verified subject"
    );
    assert_eq!(
        attestation.statement().verifier,
        trust.verifier,
        "verifier identity comes from signed admission"
    );
    assert_eq!(
        attestation.statement().verification_delegation,
        authority.payload().id,
        "attestation records the exact semantic grant"
    );
}

#[test]
fn wrong_verification_authority_is_refused() {
    let trust = TestAuthority::new();
    let verdict = verification(&trust, true, 1);
    let resource = assurance_subject_resource(&verdict.subject).expect("subject encodes");
    let admitted = trust.admit(AdmissionKind::Verification, &trust.verifier, verdict);
    let authority = trust.admit(
        AdmissionKind::Delegation,
        &trust.owner,
        trust.grant(trust.verifier.clone(), "observe-only", resource),
    );
    assert!(
        matches!(
            DelegatedVerification::admit(&admitted, &authority, &trust.context()),
            Err(VerificationAdmissionRefusal::Authority(
                AuthorityRefusal::ActionScopeMismatch
            ))
        ),
        "a descriptive verifier identity cannot replace delegated authority"
    );
}

#[test]
fn failed_or_empty_verification_cannot_be_attested() {
    let trust = TestAuthority::new();
    for (passed, evidence_count, expected) in [
        (false, 1, AttestationRefusal::VerificationFailed),
        (true, 0, AttestationRefusal::NoEvidence),
    ] {
        let verdict = verification(&trust, passed, evidence_count);
        let resource = assurance_subject_resource(&verdict.subject).expect("subject encodes");
        let admitted = trust.admit(AdmissionKind::Verification, &trust.verifier, verdict);
        let authority = trust.admit(
            AdmissionKind::Delegation,
            &trust.owner,
            trust.grant(trust.verifier.clone(), VERIFY_ASSURANCE_ACTION, resource),
        );
        let delegated = DelegatedVerification::admit(&admitted, &authority, &trust.context())
            .expect("authority is valid independently of the verdict");
        assert_eq!(
            Attestation::issue(
                &delegated,
                &trust.producer,
                PolicyBundleId::new(),
                RuntimeGenerationId::derive(b"runtime"),
                AdapterId::new(),
                DelegationId::new(),
            ),
            Err(expected),
            "verdict and evidence requirements stay distinct"
        );
    }
}

#[test]
fn verifier_cannot_attest_its_own_work() {
    let trust = TestAuthority::new();
    let verdict = verification(&trust, true, 1);
    let resource = assurance_subject_resource(&verdict.subject).expect("subject encodes");
    let admitted = trust.admit(AdmissionKind::Verification, &trust.verifier, verdict);
    let authority = trust.admit(
        AdmissionKind::Delegation,
        &trust.owner,
        trust.grant(trust.verifier.clone(), VERIFY_ASSURANCE_ACTION, resource),
    );
    let delegated = DelegatedVerification::admit(&admitted, &authority, &trust.context())
        .expect("verifier authority is valid");
    assert_eq!(
        Attestation::issue(
            &delegated,
            &trust.verifier,
            PolicyBundleId::new(),
            RuntimeGenerationId::derive(b"runtime"),
            AdapterId::new(),
            DelegationId::new(),
        ),
        Err(AttestationRefusal::VerifierIsTheSubjectActor),
        "separation is an identity check rather than a caller-provided label"
    );
}

#[test]
fn subject_swap_and_forged_digest_are_refused_on_the_wire() {
    let trust = TestAuthority::new();
    let verdict = verification(&trust, true, 1);
    let resource = assurance_subject_resource(&verdict.subject).expect("subject encodes");
    let admitted = trust.admit(AdmissionKind::Verification, &trust.verifier, verdict);
    let authority = trust.admit(
        AdmissionKind::Delegation,
        &trust.owner,
        trust.grant(trust.verifier.clone(), VERIFY_ASSURANCE_ACTION, resource),
    );
    let delegated = DelegatedVerification::admit(&admitted, &authority, &trust.context())
        .expect("verifier authority is valid");
    let attestation = Attestation::issue(
        &delegated,
        &trust.producer,
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"runtime"),
        AdapterId::new(),
        DelegationId::new(),
    )
    .expect("fixture attests");

    let mut swapped = serde_json::to_value(&attestation).expect("attestation serializes");
    swapped["statement"]["subject"] = serde_json::json!(Digest::blake3(b"other subject"));
    assert!(
        serde_json::from_value::<Attestation>(swapped).is_err(),
        "subject replay invalidates the statement digest"
    );

    let mut forged = serde_json::to_value(&attestation).expect("attestation serializes");
    forged["statement_digest"] = serde_json::json!(Digest::blake3(b"forged"));
    assert!(
        serde_json::from_value::<Attestation>(forged).is_err(),
        "caller-provided digest cannot replace recomputation"
    );
}
