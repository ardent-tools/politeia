use politeia_core::{
    AdapterId, DelegationId, Digest, EvidenceId, PolicyBundleId, PrincipalId, RuntimeGenerationId,
};

use crate::{Attestation, AttestationRefusal, IndependenceClass, Verification};

fn verification(independence: IndependenceClass, passed: bool, evidence: usize) -> Verification {
    Verification {
        subject: Digest::blake3(b"the verified subject"),
        verifier: PrincipalId::new(),
        evidence: (0..evidence).map(|_| EvidenceId::new()).collect(),
        passed,
        independence,
    }
}

fn issue(
    verification: &Verification,
    actor: &PrincipalId,
) -> Result<Attestation, AttestationRefusal> {
    Attestation::issue(
        verification,
        actor,
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"runtime generation"),
        AdapterId::new(),
        DelegationId::new(),
    )
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn an_independent_passing_verification_may_be_attested() {
    let v = verification(IndependenceClass::IndependentService, true, 1);
    let attestation = issue(&v, &PrincipalId::new()).expect("this one attests");

    assert!(attestation.covers(&v.subject));
    assert_eq!(attestation.statement().verifier, v.verifier);
    assert_eq!(
        attestation.statement_digest(),
        &attestation
            .statement()
            .digest()
            .expect("the statement encodes"),
        "the recorded digest is the digest of what it sits beside"
    );
}

#[test]
fn a_failed_verification_cannot_be_attested() {
    assert_eq!(
        issue(
            &verification(IndependenceClass::IndependentService, false, 1),
            &PrincipalId::new()
        ),
        Err(AttestationRefusal::VerificationFailed)
    );
}

#[test]
fn a_verdict_citing_no_evidence_cannot_be_attested() {
    // A verdict resting on nothing is an opinion. The detector/claim separation
    // in `docs/06-POLICY_COMPILER.md` exists so a verdict has to name what it
    // read.
    assert_eq!(
        issue(
            &verification(IndependenceClass::IndependentService, true, 0),
            &PrincipalId::new()
        ),
        Err(AttestationRefusal::NoEvidence)
    );
}

#[test]
fn a_self_reported_verification_cannot_be_attested() {
    // `IndependenceClass::SelfReported` documents itself as never satisfying an
    // independent-verification obligation. This is where that stops being
    // documentation.
    assert_eq!(
        issue(
            &verification(IndependenceClass::SelfReported, true, 1),
            &PrincipalId::new()
        ),
        Err(AttestationRefusal::SelfCertified)
    );
}

#[test]
fn a_verifier_judging_its_own_work_cannot_be_attested() {
    // Distinct from the class, and the distinction is the point: a verifier can
    // honestly record itself as an independent service and still *be* the actor
    // under judgement. The class is a claim; this is a comparison.
    let v = verification(IndependenceClass::IndependentService, true, 1);
    let itself = v.verifier.clone();
    assert_eq!(
        issue(&v, &itself),
        Err(AttestationRefusal::VerifierIsTheSubjectActor)
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn an_attestation_does_not_cover_another_subject() {
    let v = verification(IndependenceClass::IndependentService, true, 1);
    let attestation = issue(&v, &PrincipalId::new()).expect("this one attests");
    assert!(!attestation.covers(&Digest::blake3(b"different work entirely")));
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn a_legal_attestation_round_trips() {
    let v = verification(IndependenceClass::HumanAuthority, true, 2);
    let attestation = issue(&v, &PrincipalId::new()).expect("this one attests");
    let text = serde_json::to_string(&attestation).expect("an attestation serializes");
    assert_eq!(
        serde_json::from_str::<Attestation>(&text).expect("and deserializes"),
        attestation
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn a_subject_swapped_on_the_wire_is_refused() {
    // "Attestation cannot be replayed for a different subject"
    // (`docs/18-FIRST_VERTICAL_SLICE.md`), enforced rather than asserted: the
    // digest covers the subject along with everything else bound, so moving the
    // subject leaves a digest that no longer describes the statement.
    let v = verification(IndependenceClass::IndependentService, true, 1);
    let attestation = issue(&v, &PrincipalId::new()).expect("this one attests");
    let mut wire: serde_json::Value =
        serde_json::to_value(&attestation).expect("an attestation serializes");
    wire["statement"]["subject"] = serde_json::json!(Digest::blake3(b"someone else's work"));

    assert!(
        serde_json::from_value::<Attestation>(wire).is_err(),
        "an attestation moved to another subject must not deserialize"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be attested is a broken test, not a finding"
)]
fn a_forged_statement_digest_is_refused() {
    // The direction a public field left open. Deserialization is the only way
    // an attestation enters from outside this crate, and it recomputes.
    let v = verification(IndependenceClass::IndependentService, true, 1);
    let attestation = issue(&v, &PrincipalId::new()).expect("this one attests");
    let mut wire: serde_json::Value =
        serde_json::to_value(&attestation).expect("an attestation serializes");
    wire["statement_digest"] = serde_json::json!(Digest::blake3(b"a digest of nothing"));

    assert!(serde_json::from_value::<Attestation>(wire).is_err());
}

#[test]
fn every_refusal_variant_names_the_test_that_reaches_it() {
    // `StatementDigestMismatch` and `Encoding` are reached through
    // deserialization rather than through `issue`, so they are named by the
    // wire tests above; `Encoding` needs a statement that cannot encode, which
    // no field of `AttestationStatement` can produce.
    let reached_by = |refusal: &AttestationRefusal| -> &'static str {
        match refusal {
            AttestationRefusal::VerificationFailed => "a_failed_verification_cannot_be_attested",
            AttestationRefusal::NoEvidence => "a_verdict_citing_no_evidence_cannot_be_attested",
            AttestationRefusal::SelfCertified => "a_self_reported_verification_cannot_be_attested",
            AttestationRefusal::VerifierIsTheSubjectActor => {
                "a_verifier_judging_its_own_work_cannot_be_attested"
            }
            AttestationRefusal::StatementDigestMismatch => "a_forged_statement_digest_is_refused",
            AttestationRefusal::Encoding(_) => "(unreachable; no field can fail to encode)",
        }
    };
    assert_eq!(
        reached_by(&AttestationRefusal::SelfCertified),
        "a_self_reported_verification_cannot_be_attested"
    );
}
