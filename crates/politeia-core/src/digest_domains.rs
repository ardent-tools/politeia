//! Evidence that a digest identifies a record's domain, not only its bytes.
//!
//! `blake3` is a function of bytes alone. Before domain separation, two records
//! whose encodings coincided received one identity — and a digest here is a
//! binding rather than a checksum: the dispatcher admits an execution
//! assignment by comparing one. These tests hold the separation in place.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{Digest, DigestDomain, domained_bytes};

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
///
/// WHY the fields are declared out of alphabetical order: canonical encoding
/// sorts them, and a fixture already in sorted order encodes identically under
/// a canonicalizer and under plain `serde_json`. It would pass either way and
/// witness neither.
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
fn the_digest_pre_image_is_pinned_so_the_vectors_stay_re_derivable() {
    // The golden digests below are opaque: a differing hex string says the
    // encoding moved and nothing about which rule moved it. This pins the bytes
    // that get hashed, so the same failure names the cause -- a key out of
    // order, whitespace, a field appearing or vanishing -- and so any reader
    // can recompute the vectors with a stock blake3 and no politeia code.
    let bytes = domained_bytes(DigestDomain::EvidenceRecord, &payload())
        .expect("the fixture payload must encode");
    assert_eq!(
        String::from_utf8(bytes).expect("canonical bytes are UTF-8"),
        r#"{"kind":"evidence_record_v1","value":{"count":1,"name":"politeia"}}"#,
        "the digest pre-image changed shape"
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
            "9401e7a0200dd896265e71af00db2b0c3cc12f28606936e815ef9f7bc3dd81fe",
        ),
        (
            "availability_snapshot_v1",
            "440dc7d52ef2ac4b24628ca41c23a8e8d7f03a838b07902eca680fcba9b493b1",
        ),
        (
            "capability_profile_v1",
            "3fc8f6036a41d684456f79d290d61612e66245c07c6cf11b39f786656b0b9ab7",
        ),
        (
            "capability_verification_v1",
            "50f54c1a1ebfa9416f394572442bc594b37bc6626101ec8797c44b3ed0c904cf",
        ),
        (
            "commissioning_record_v1",
            "2bae1332172528fa041d04e2804907ac0aefc08a586c6cb5b6beca6aaa27d9b1",
        ),
        (
            "evidence_record_v1",
            "6db9737c968245077bd1e329b664fdc7064b641c63c60e6c69fcab0125e0ae0a",
        ),
        (
            "execution_assignment_v1",
            "07e846e089da5434abb26cb335ec1d0e3d9ce8be0cb80d9e5ee2509fcfbc8431",
        ),
        (
            "execution_requirement_v1",
            "b76b18cf9200fa3bbce33414c506c3851af55192f2481a978edc01293732ecad",
        ),
        (
            "execution_resource_v1",
            "2e00ba444d1321220a1cd988742bc3c34bc885ebea916901d78cd2ed8a516e84",
        ),
        (
            "lease_claims_v1",
            "829cbc3e7fdb034b2da4f11649aaaa1b045e70cae696d35c728507bcefff8eef",
        ),
        (
            "operation_intent_v1",
            "c33cf344021273b4fe53b8d0c4bfd1da9359fc389f39756a582c6fd74b522e55",
        ),
        (
            "routing_decision_v1",
            "d84ab38efeca1e23795ebf20383dee9ccf9634f26a93897971b38787658c7b4a",
        ),
        (
            "runtime_generation_inputs_v1",
            "eb9474a0fb0567cd22293ee474111dc6d66c75776d763277a832901b2aa24d2c",
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
