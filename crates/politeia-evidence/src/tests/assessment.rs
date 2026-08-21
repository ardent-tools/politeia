use std::collections::{BTreeMap, BTreeSet};

use jiff::{SignedDuration, Timestamp};
use politeia_core::evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry};
use politeia_core::{
    DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, PrincipalId, ResourceBudget,
};

use crate::assessment::{
    AssessmentError, AssessmentRelation, CORRECT_ACTION, Projection, RelationKind,
    SUPERSEDE_ACTION, Unresolved, project,
};

#[expect(
    clippy::expect_used,
    reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
)]
fn now() -> Timestamp {
    "2026-08-21T00:00:00Z"
        .parse()
        .expect("the fixture timestamp is valid RFC 3339")
}

fn subject_a() -> Digest {
    Digest::blake3(b"subject a")
}

fn subject_b() -> Digest {
    Digest::blake3(b"subject b")
}

fn record(subject: &Digest, method: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::new(),
        subject: subject.clone(),
        producer: PrincipalId::new(),
        producer_delegation: DelegationId::new(),
        method: method.to_string(),
        payload_digest: Digest::blake3(method.as_bytes()),
        observed_at: now(),
        independence: IndependenceClass::IndependentService,
    }
}

fn delegation(subject: PrincipalId, actions: &[&str], expires_at: Timestamp) -> Delegation {
    Delegation {
        id: DelegationId::new(),
        issuer: PrincipalId::new(),
        subject,
        parent: None,
        actions: actions.iter().map(|action| (*action).to_string()).collect(),
        resources: BTreeSet::from(["evidence:*".to_string()]),
        effects: BTreeSet::from([Effect::ReadExternalSystem]),
        data_classes: BTreeSet::from([DataClass::Public]),
        audience: BTreeSet::from(["evidence-store".to_string()]),
        expires_at,
        budget: ResourceBudget {
            wall_ms: Some(1),
            cpu_ms: Some(1),
            memory_bytes: Some(1),
            io_bytes: Some(1),
            network_bytes: Some(1),
            external_cost_microunits: Some(1),
        },
    }
}

/// An authority holding both relation actions, valid well past the fixtures.
struct Authority {
    principal: PrincipalId,
    delegation: Delegation,
}

fn authority() -> Authority {
    let principal = PrincipalId::new();
    let delegation = delegation(
        principal.clone(),
        &[CORRECT_ACTION, SUPERSEDE_ACTION],
        now() + SignedDuration::from_hours(24),
    );
    Authority {
        principal,
        delegation,
    }
}

fn trusted(delegations: &[&Delegation]) -> BTreeMap<DelegationId, Delegation> {
    delegations
        .iter()
        .map(|delegation| (delegation.id.clone(), (*delegation).clone()))
        .collect()
}

fn relation(
    kind: RelationKind,
    prior: &EvidenceRecord,
    successor: &EvidenceRecord,
    authority: &Authority,
) -> AssessmentRelation {
    AssessmentRelation {
        id: EvidenceId::new(),
        kind,
        prior: prior.id.clone(),
        successor: successor.id.clone(),
        authority: authority.principal.clone(),
        authority_delegation: authority.delegation.id.clone(),
        asserted_at: now(),
    }
}

#[expect(
    clippy::expect_used,
    reason = "a registry fixture that repeats an identity is a broken test, not a finding"
)]
fn registry(records: &[&EvidenceRecord]) -> TrustedEvidenceRegistry {
    TrustedEvidenceRegistry::from_trusted_bootstrap(records.iter().map(|r| (*r).clone()))
        .expect("fixture records have distinct identities")
}

#[test]
fn a_supersession_chain_selects_its_terminal_record() {
    let (first, second, third) = (
        record(&subject_a(), "first"),
        record(&subject_a(), "second"),
        record(&subject_a(), "third"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Supersession, &first, &second, &authority),
        relation(RelationKind::Supersession, &second, &third, &authority),
    ];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&first, &second, &third]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Current {
            record: third.id.clone(),
            corrections: Vec::new(),
        })
    );
}

#[test]
fn a_correction_amends_the_live_record_without_replacing_it() {
    // The distinction the two relation kinds exist for: a correction leaves the
    // corrected record as the subject of the assessment, so the projection
    // still names it and carries the amendment alongside.
    let (original, amendment) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "amendment"),
    );
    let authority = authority();
    let relations = [relation(
        RelationKind::Correction,
        &original,
        &amendment,
        &authority,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &amendment]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Current {
            record: original.id.clone(),
            corrections: vec![amendment.id.clone()],
        })
    );
}

#[test]
fn corrections_chain_from_nearest_to_furthest() {
    let (original, first, second) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "first amendment"),
        record(&subject_a(), "second amendment"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Correction, &original, &first, &authority),
        relation(RelationKind::Correction, &first, &second, &authority),
    ];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &first, &second]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Current {
            record: original.id.clone(),
            corrections: vec![first.id.clone(), second.id.clone()],
        })
    );
}

#[test]
fn a_forked_supersession_is_unresolved_rather_than_ordered() {
    // Two successors of one record. A reducer that ordered by timestamp would
    // answer here, confidently, and the evidence says nothing about which is
    // current.
    let (original, left, right) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "left"),
        record(&subject_a(), "right"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Supersession, &original, &left, &authority),
        relation(RelationKind::Supersession, &original, &right, &authority),
    ];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &left, &right]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Unresolved(Unresolved::ForkedSuccession {
            prior: original.id.clone(),
        }))
    );
}

#[test]
fn two_unrelated_live_records_are_unresolved() {
    // Neither supersedes the other, so nothing in the evidence says which is
    // current. This is the case a newest-timestamp shortcut exists to paper
    // over.
    let (one, two, three) = (
        record(&subject_a(), "one"),
        record(&subject_a(), "two"),
        record(&subject_a(), "three"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Supersession, &one, &two, &authority),
        relation(RelationKind::Correction, &three, &one, &authority),
    ];

    let projected = project(
        &subject_a(),
        &registry(&[&one, &two, &three]),
        &relations,
        &trusted(&[&authority.delegation]),
    );
    assert!(
        matches!(
            projected,
            Ok(Projection::Unresolved(
                Unresolved::CompetingLiveRecords { .. }
            ))
        ),
        "two live records must be unresolved, got {projected:?}"
    );
}

#[test]
fn a_supersession_cycle_is_unresolved() {
    let (one, two) = (record(&subject_a(), "one"), record(&subject_a(), "two"));
    let authority = authority();
    let relations = [
        relation(RelationKind::Supersession, &one, &two, &authority),
        relation(RelationKind::Supersession, &two, &one, &authority),
    ];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&one, &two]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Unresolved(Unresolved::Cycle))
    );
}

#[test]
fn conflicting_corrections_of_one_record_are_unresolved() {
    let (original, left, right) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "left reading"),
        record(&subject_a(), "right reading"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Correction, &original, &left, &authority),
        relation(RelationKind::Correction, &original, &right, &authority),
    ];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &left, &right]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Unresolved(Unresolved::ConflictingCorrections {
            corrected: original.id.clone(),
        }))
    );
}

#[test]
fn a_cross_subject_relation_is_refused() {
    // The substitution that would let an assessment of one subject be replaced
    // by evidence about another.
    let (mine, theirs) = (record(&subject_a(), "mine"), record(&subject_b(), "theirs"));
    let authority = authority();
    let relations = [relation(
        RelationKind::Supersession,
        &mine,
        &theirs,
        &authority,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&mine, &theirs]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Err(AssessmentError::CrossSubject {
            relation: relations[0].id.clone(),
        })
    );
}

#[test]
fn a_relation_naming_an_unadmitted_record_is_refused() {
    let (known, unknown) = (
        record(&subject_a(), "known"),
        record(&subject_a(), "never admitted"),
    );
    let authority = authority();
    let relations = [relation(
        RelationKind::Supersession,
        &known,
        &unknown,
        &authority,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&known]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Err(AssessmentError::UnknownRecord {
            relation: relations[0].id.clone(),
            record: unknown.id.clone(),
        })
    );
}

#[test]
fn a_relation_without_the_delegated_action_is_refused() {
    // The delegation is trusted, unexpired, and held by the asserting
    // principal. It simply does not carry the action, which is what separates
    // "this principal is known" from "this principal may amend the record".
    let (original, amendment) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "amendment"),
    );
    let principal = PrincipalId::new();
    let holder = Authority {
        delegation: delegation(
            principal.clone(),
            &[SUPERSEDE_ACTION],
            now() + SignedDuration::from_hours(24),
        ),
        principal,
    };
    let relations = [relation(
        RelationKind::Correction,
        &original,
        &amendment,
        &holder,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &amendment]),
            &relations,
            &trusted(&[&holder.delegation]),
        ),
        Err(AssessmentError::ActionNotDelegated {
            relation: relations[0].id.clone(),
            action: CORRECT_ACTION,
        })
    );
}

#[test]
fn a_relation_citing_another_principals_delegation_is_refused() {
    let (original, amendment) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "amendment"),
    );
    let holder = authority();
    let mut asserted = relation(RelationKind::Correction, &original, &amendment, &holder);
    asserted.authority = PrincipalId::new();

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &amendment]),
            &[asserted.clone()],
            &trusted(&[&holder.delegation]),
        ),
        Err(AssessmentError::AuthorityMismatch {
            relation: asserted.id,
        })
    );
}

#[test]
fn a_relation_asserted_under_an_expired_delegation_is_refused() {
    let (original, amendment) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "amendment"),
    );
    let principal = PrincipalId::new();
    let holder = Authority {
        delegation: delegation(
            principal.clone(),
            &[CORRECT_ACTION],
            now() - SignedDuration::from_hours(1),
        ),
        principal,
    };
    let relations = [relation(
        RelationKind::Correction,
        &original,
        &amendment,
        &holder,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &amendment]),
            &relations,
            &trusted(&[&holder.delegation]),
        ),
        Err(AssessmentError::StaleAuthority {
            relation: relations[0].id.clone(),
        })
    );
}

#[test]
fn authority_is_judged_at_assertion_time_rather_than_projection_time() {
    // A relation asserted while its delegation was live stays admissible after
    // the delegation lapses. Whether the authority held then is a fact about
    // then, and re-judging it later would make a stored assessment change
    // meaning because time passed.
    let (original, replacement) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "replacement"),
    );
    let principal = PrincipalId::new();
    let expiry = now() + SignedDuration::from_hours(1);
    let holder = Authority {
        delegation: delegation(principal.clone(), &[SUPERSEDE_ACTION], expiry),
        principal,
    };
    let mut asserted = relation(RelationKind::Supersession, &original, &replacement, &holder);
    asserted.asserted_at = expiry - SignedDuration::from_mins(1);

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &replacement]),
            &[asserted],
            &trusted(&[&holder.delegation]),
        ),
        Ok(Projection::Current {
            record: replacement.id.clone(),
            corrections: Vec::new(),
        })
    );
}

#[test]
fn a_repeated_relation_identity_is_refused() {
    let (original, replacement) = (
        record(&subject_a(), "original"),
        record(&subject_a(), "replacement"),
    );
    let authority = authority();
    let asserted = relation(
        RelationKind::Supersession,
        &original,
        &replacement,
        &authority,
    );

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original, &replacement]),
            &[asserted.clone(), asserted.clone()],
            &trusted(&[&authority.delegation]),
        ),
        Err(AssessmentError::DuplicateRelation {
            relation: asserted.id,
        })
    );
}

#[test]
fn a_record_may_not_supersede_itself() {
    let original = record(&subject_a(), "original");
    let authority = authority();
    let mut asserted = relation(RelationKind::Supersession, &original, &original, &authority);
    asserted.successor = original.id.clone();

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&original]),
            &[asserted.clone()],
            &trusted(&[&authority.delegation]),
        ),
        Err(AssessmentError::SelfRelation {
            relation: asserted.id,
        })
    );
}

#[test]
fn a_subject_no_relation_reaches_has_no_assessment() {
    let elsewhere = record(&subject_b(), "elsewhere");
    let other = record(&subject_b(), "other");
    let authority = authority();
    let relations = [relation(
        RelationKind::Supersession,
        &elsewhere,
        &other,
        &authority,
    )];

    assert_eq!(
        project(
            &subject_a(),
            &registry(&[&elsewhere, &other]),
            &relations,
            &trusted(&[&authority.delegation]),
        ),
        Ok(Projection::Unresolved(Unresolved::NoRecords))
    );
}

#[test]
fn the_projection_does_not_depend_on_the_order_of_its_inputs() {
    // The reproducibility claim. A journal replayed in a different order is the
    // same journal, and a reducer that quietly depended on arrival order would
    // pass every test above -- each of which presents its relations once, in
    // one order.
    let (first, second, third, amendment) = (
        record(&subject_a(), "first"),
        record(&subject_a(), "second"),
        record(&subject_a(), "third"),
        record(&subject_a(), "amendment"),
    );
    let authority = authority();
    let mut relations = vec![
        relation(RelationKind::Supersession, &first, &second, &authority),
        relation(RelationKind::Supersession, &second, &third, &authority),
        relation(RelationKind::Correction, &third, &amendment, &authority),
    ];
    let store = registry(&[&first, &second, &third, &amendment]);
    let delegations = trusted(&[&authority.delegation]);

    let expected = project(&subject_a(), &store, &relations, &delegations);
    assert_eq!(
        expected,
        Ok(Projection::Current {
            record: third.id.clone(),
            corrections: vec![amendment.id.clone()],
        })
    );

    // Every rotation, not one shuffle: a single reordering can miss a
    // dependence that only shows when a particular pair swaps.
    for _ in 0..relations.len() {
        relations.rotate_left(1);
        assert_eq!(
            project(&subject_a(), &store, &relations, &delegations),
            expected,
            "the projection changed with the order of an unchanged journal"
        );
    }
    relations.reverse();
    assert_eq!(
        project(&subject_a(), &store, &relations, &delegations),
        expected,
        "the projection changed when the journal was replayed backwards"
    );
}

#[test]
fn a_relation_about_another_subject_does_not_disturb_this_one() {
    // Journals hold every subject's relations. A projection that read them all
    // would report competing live records for a subject whose own evidence is
    // unambiguous.
    let (mine, replacement) = (
        record(&subject_a(), "mine"),
        record(&subject_a(), "replacement"),
    );
    let (theirs, their_replacement) = (
        record(&subject_b(), "theirs"),
        record(&subject_b(), "their replacement"),
    );
    let authority = authority();
    let relations = [
        relation(RelationKind::Supersession, &mine, &replacement, &authority),
        relation(
            RelationKind::Supersession,
            &theirs,
            &their_replacement,
            &authority,
        ),
    ];
    let store = registry(&[&mine, &replacement, &theirs, &their_replacement]);
    let delegations = trusted(&[&authority.delegation]);

    assert_eq!(
        project(&subject_a(), &store, &relations, &delegations),
        Ok(Projection::Current {
            record: replacement.id.clone(),
            corrections: Vec::new(),
        })
    );
    assert_eq!(
        project(&subject_b(), &store, &relations, &delegations),
        Ok(Projection::Current {
            record: their_replacement.id.clone(),
            corrections: Vec::new(),
        })
    );
}
