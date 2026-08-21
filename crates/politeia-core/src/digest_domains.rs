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
        ("approved_generation_inputs_v1", "GOLDEN"),
        ("availability_snapshot_v1", "GOLDEN"),
        ("capability_profile_v1", "GOLDEN"),
        ("capability_verification_v1", "GOLDEN"),
        ("commissioning_record_v1", "GOLDEN"),
        ("evidence_record_v1", "GOLDEN"),
        ("execution_assignment_v1", "GOLDEN"),
        ("execution_requirement_v1", "GOLDEN"),
        ("execution_resource_v1", "GOLDEN"),
        ("lease_claims_v1", "GOLDEN"),
        ("operation_intent_v1", "GOLDEN"),
        ("routing_decision_v1", "GOLDEN"),
        ("runtime_generation_inputs_v1", "GOLDEN"),
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
