//! Evidence that a digest identifies a record's domain, not only its bytes.
//!
//! `blake3` is a function of bytes alone. Before domain separation, two records
//! whose encodings coincided received one identity — and a digest here is a
//! binding rather than a checksum: the dispatcher admits an execution
//! assignment by comparing one. These tests hold the separation in place.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{Digest, DigestDomain};

/// Every domain, in a form that cannot go stale.
///
/// WHY the exhaustive match: a hand-kept list silently omits a variant added
/// later, and the omission is invisible — every test below keeps passing while
/// covering one domain less. Matching exhaustively means a new variant stops
/// the build until it is listed.
fn all_domains() -> Vec<DigestDomain> {
    let complete = |domain: DigestDomain| match domain {
        DigestDomain::EvidenceRecord
        | DigestDomain::CommissioningRecord
        | DigestDomain::ApprovedGenerationInputs
        | DigestDomain::RuntimeGenerationInputs
        | DigestDomain::OperationIntent
        | DigestDomain::LeaseClaims
        | DigestDomain::ExecutionResource
        | DigestDomain::CapabilityProfile
        | DigestDomain::CapabilityVerification
        | DigestDomain::AvailabilitySnapshot
        | DigestDomain::ExecutionRequirement
        | DigestDomain::RoutingDecision
        | DigestDomain::ExecutionAssignment => (),
    };

    let domains = vec![
        DigestDomain::EvidenceRecord,
        DigestDomain::CommissioningRecord,
        DigestDomain::ApprovedGenerationInputs,
        DigestDomain::RuntimeGenerationInputs,
        DigestDomain::OperationIntent,
        DigestDomain::LeaseClaims,
        DigestDomain::ExecutionResource,
        DigestDomain::CapabilityProfile,
        DigestDomain::CapabilityVerification,
        DigestDomain::AvailabilitySnapshot,
        DigestDomain::ExecutionRequirement,
        DigestDomain::RoutingDecision,
        DigestDomain::ExecutionAssignment,
    ];
    for domain in &domains {
        complete(*domain);
    }
    domains
}

/// A payload with nothing domain-specific about it, so the only thing that can
/// distinguish two digests of it is the domain itself.
#[derive(Serialize)]
struct Payload {
    name: &'static str,
    count: u8,
}

fn payload() -> Payload {
    Payload {
        name: "politeia",
        count: 1,
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a payload that cannot encode is a broken fixture, not a finding"
)]
fn the_same_payload_digests_differently_in_every_domain() {
    let digests: BTreeSet<String> = all_domains()
        .into_iter()
        .map(|domain| {
            Digest::of(domain, &payload())
                .expect("the fixture payload must encode")
                .as_str()
                .to_owned()
        })
        .collect();

    assert_eq!(
        digests.len(),
        all_domains().len(),
        "two domains produced the same digest for identical payload bytes, \
         which is the collision domain separation exists to prevent"
    );
}

#[test]
fn every_domain_tag_is_distinct() {
    // The tag is the only thing separating the domains, so two domains sharing
    // one collapses them silently — every digest still computes, and two record
    // classes quietly share an identity space.
    let tags: BTreeSet<&'static str> = all_domains().iter().map(|d| d.tag()).collect();
    assert_eq!(
        tags.len(),
        all_domains().len(),
        "two domains share a tag: {tags:?}"
    );
}

#[test]
fn every_domain_tag_carries_a_version() {
    // Tags are append-only. A tag without a version has nowhere to go when the
    // encoding changes, and the next author edits it in place — invalidating
    // every stored binding that cites it, with nothing to notice.
    for domain in all_domains() {
        let tag = domain.tag();
        assert!(
            tag.rsplit_once("_v")
                .is_some_and(|(_, v)| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit())),
            "{tag} does not end in a version suffix"
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a payload that cannot encode is a broken fixture, not a finding"
)]
fn changing_one_field_changes_the_digest() {
    let domain = DigestDomain::EvidenceRecord;
    let base = Digest::of(domain, &payload()).expect("the fixture payload must encode");

    let changed_value = Digest::of(
        domain,
        &Payload {
            name: "politeia",
            count: 2,
        },
    )
    .expect("the fixture payload must encode");
    assert_ne!(
        base, changed_value,
        "changing a value left the digest equal"
    );

    let changed_name = Digest::of(
        domain,
        &Payload {
            name: "politeia ",
            count: 1,
        },
    )
    .expect("the fixture payload must encode");
    assert_ne!(
        base, changed_name,
        "a trailing space left the digest equal, so the encoding is lossy"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "a payload that cannot encode is a broken fixture, not a finding"
)]
fn golden_vectors_pin_the_envelope_encoding() {
    // These are the published bytes. They change only when the digest envelope
    // changes -- a renamed field, a reordered one, a different encoder -- which
    // is precisely the event that silently invalidates every stored binding and
    // which no self-referential test can see. A test that hashes twice and
    // compares agrees with itself under any encoding.
    //
    // Regenerating them is a deliberate act: it means every digest of that
    // domain has moved.
    let expected: BTreeMap<&'static str, &'static str> = BTreeMap::from([
        (
            "approved_generation_inputs_v1",
            "7bc7ceb965936bbbcb1e0317241dcc46ca6042aaf071c50ac4c491d0248a4d97",
        ),
        (
            "availability_snapshot_v1",
            "b4f43e3ddf90230e6e1ea8429b22ca34e6bfc7ba31e1243ff1450a4a81032fcf",
        ),
        (
            "capability_profile_v1",
            "afe5f1a279000f6f9c01277795188f3e1c4a1b77399244c4c519b9485e3845eb",
        ),
        (
            "capability_verification_v1",
            "d4fbd01dd61ccf68ae0b0d1965ebab8250c4386942e9377226d1fb76dc2f590b",
        ),
        (
            "commissioning_record_v1",
            "5808d5de9a2b36823baf452544b83261fadb84c4b204f7bad0202ecf9fefd97f",
        ),
        (
            "evidence_record_v1",
            "b7196a02ce671f7af44204d3e8d3b83e4314b633994d39eb57ba079bbc734aeb",
        ),
        (
            "execution_assignment_v1",
            "e02a9ba46364ac05e428241e69e22d8ee1b870bd941f4b996d31972687e5a13c",
        ),
        (
            "execution_requirement_v1",
            "a451cabc0a66e4ae816dee9d7526c4eda81cdd191410ef6b11afede9d4a799c2",
        ),
        (
            "execution_resource_v1",
            "6e63e3bc9c273067c484b2841b2be681e517f2b02f8dfd4bd6764209d5489d66",
        ),
        (
            "lease_claims_v1",
            "037a56021021a8195d73380ece70673ceb470acda98cfbcfb431a84056f6cb0c",
        ),
        (
            "operation_intent_v1",
            "e5fadd59e9d9b38a3f936f56c0b8640eb43fc41d7a1985905a80e9074fc0a8e5",
        ),
        (
            "routing_decision_v1",
            "ac9f98d4aa6dced8c5c11b84972d77235f8cbbb4d3a1e0c66f2da9294c894e54",
        ),
        (
            "runtime_generation_inputs_v1",
            "2d087b07cccde1ce126575aad94610fb0be4a323d0074f4af0e7162c7c8eb78d",
        ),
    ]);

    let actual: BTreeMap<&'static str, String> = all_domains()
        .into_iter()
        .map(|domain| {
            (
                domain.tag(),
                Digest::of(domain, &payload())
                    .expect("the fixture payload must encode")
                    .as_str()
                    .to_owned(),
            )
        })
        .collect();

    let expected_owned: BTreeMap<&'static str, String> = expected
        .into_iter()
        .map(|(tag, hex)| (tag, hex.to_owned()))
        .collect();

    assert_eq!(
        actual, expected_owned,
        "the digest envelope encoding changed; every stored binding in the \
         differing domains is now unmatchable"
    );
}
