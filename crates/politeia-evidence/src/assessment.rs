//! Correction and supersession relations, and the projection over them.
//!
//! Evidence is append-only, so an assessment that turns out wrong is not
//! edited. A [`Correction`] amends the interpretation of a record that stays
//! the subject; a [`Supersession`] selects a different record for future use
//! and leaves the prior one intact. Neither rewrites history, which is what
//! `docs/09-PERSISTENCE.md` requires and what makes a stored decision still
//! readable as what its recipient actually observed.
//!
//! The whole difficulty is what a consumer should believe when several records
//! exist. `docs/09-PERSISTENCE.md` is explicit that supersession is a directed
//! relation over exact subjects and **not a newest-timestamp shortcut**, and
//! that multiple live successors, cycles, or conflicting corrections produce an
//! explicit unresolved view rather than a winner.
//!
//! WHY that matters more than it sounds: a reducer that always returns an
//! answer is indistinguishable, at every call site, from one that knows the
//! answer. Ordering by timestamp would always return something, would look
//! reasonable in every test written from a happy path, and would silently pick
//! a side in exactly the cases where a human needs to be told there is a
//! dispute. [`Projection::Unresolved`] is the value this module exists to be
//! able to return.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::evidence::{EvidenceRecord, TrustedEvidenceRegistry};
use politeia_core::{Delegation, DelegationId, Digest, EvidenceId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The semantic action a delegation must carry to amend an interpretation.
pub const CORRECT_ACTION: &str = "evidence.correct";

/// The semantic action a delegation must carry to select a newer record.
pub const SUPERSEDE_ACTION: &str = "evidence.supersede";

/// What a relation does to the record it names.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// Amends the interpretation of a record that remains the subject.
    Correction,
    /// Selects a different record for future use, preserving the prior one.
    Supersession,
}

impl RelationKind {
    /// The semantic action a delegation must carry to assert this relation.
    pub const fn required_action(self) -> &'static str {
        match self {
            RelationKind::Correction => CORRECT_ACTION,
            RelationKind::Supersession => SUPERSEDE_ACTION,
        }
    }
}

/// A directed, authorized relation between two admitted evidence records.
///
/// WHY one type for both kinds rather than two: the graph algebra is identical
/// -- both are directed edges over exact record identities, and both are
/// checked for the same cycles, forks and cross-subject substitutions. What
/// differs is what the projection does with the edge, and that is one match.
/// Two structurally identical types would duplicate every validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentRelation {
    /// This relation's own identity as an appended record.
    pub id: EvidenceId,
    /// What the relation does.
    pub kind: RelationKind,
    /// The record being corrected or superseded.
    pub prior: EvidenceId,
    /// The record that amends or replaces it.
    pub successor: EvidenceId,
    /// The principal asserting the relation.
    pub authority: PrincipalId,
    /// The exact delegation the authority acted under.
    pub authority_delegation: DelegationId,
    /// Trusted time the relation was admitted.
    pub asserted_at: Timestamp,
}

/// The relation set could not be admitted at all.
///
/// Distinct from [`Projection::Unresolved`], and the distinction is the point:
/// these say the *input* is invalid, so no projection over it means anything.
/// An unresolved projection says the input was valid and does not determine a
/// unique current record, which is a fact about the evidence rather than a
/// fault in it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssessmentError {
    /// A relation named a record the trusted registry does not hold.
    UnknownRecord {
        /// The relation that named it.
        relation: EvidenceId,
        /// The identity that resolved to nothing.
        record: EvidenceId,
    },
    /// A relation joined two records about different subjects.
    CrossSubject {
        /// The relation that joined them.
        relation: EvidenceId,
    },
    /// A relation named the same record on both ends.
    SelfRelation {
        /// The relation that did so.
        relation: EvidenceId,
    },
    /// Two relations shared one identity.
    DuplicateRelation {
        /// The repeated identity.
        relation: EvidenceId,
    },
    /// The asserting delegation is not in the trusted set.
    UnknownAuthority {
        /// The relation that cited it.
        relation: EvidenceId,
        /// The delegation that resolved to nothing.
        delegation: DelegationId,
    },
    /// The asserting delegation was not issued to the asserting principal.
    AuthorityMismatch {
        /// The relation whose authority does not hold its delegation.
        relation: EvidenceId,
    },
    /// The asserting delegation does not carry the required action.
    ActionNotDelegated {
        /// The relation that lacked it.
        relation: EvidenceId,
        /// The action the relation kind requires.
        action: &'static str,
    },
    /// The asserting delegation had expired when the relation was asserted.
    StaleAuthority {
        /// The relation asserted under it.
        relation: EvidenceId,
    },
}

impl std::fmt::Display for AssessmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssessmentError::UnknownRecord { relation, record } => write!(
                formatter,
                "relation {relation:?} names record {record:?}, which the trusted registry does not hold"
            ),
            AssessmentError::CrossSubject { relation } => write!(
                formatter,
                "relation {relation:?} joins records about different subjects"
            ),
            AssessmentError::SelfRelation { relation } => write!(
                formatter,
                "relation {relation:?} names one record as both prior and successor"
            ),
            AssessmentError::DuplicateRelation { relation } => {
                write!(formatter, "relation identity {relation:?} appears twice")
            }
            AssessmentError::UnknownAuthority {
                relation,
                delegation,
            } => write!(
                formatter,
                "relation {relation:?} cites delegation {delegation:?}, which is not trusted"
            ),
            AssessmentError::AuthorityMismatch { relation } => write!(
                formatter,
                "relation {relation:?} cites a delegation issued to another principal"
            ),
            AssessmentError::ActionNotDelegated { relation, action } => write!(
                formatter,
                "relation {relation:?} requires the delegated action {action}"
            ),
            AssessmentError::StaleAuthority { relation } => write!(
                formatter,
                "relation {relation:?} was asserted under an expired delegation"
            ),
        }
    }
}

impl std::error::Error for AssessmentError {}

/// Why no unique current record follows from a valid relation set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unresolved {
    /// The subject has no admitted records at all.
    NoRecords,
    /// A record is superseded by more than one live successor.
    ForkedSuccession {
        /// The record with competing successors.
        prior: EvidenceId,
    },
    /// Supersession leads in a circle, so nothing is terminal.
    Cycle,
    /// Several records are live and none supersedes the others.
    ///
    /// WHY this is unresolved rather than a choice: two independent
    /// observations of one subject are exactly the case where a timestamp
    /// ordering would answer confidently and wrongly. Nothing in the evidence
    /// says which is current, so nothing here says either.
    CompetingLiveRecords {
        /// Every live record, in identity order.
        live: Vec<EvidenceId>,
    },
    /// One record carries more than one correction and none of them is ordered
    /// against the others.
    ConflictingCorrections {
        /// The record corrected more than once.
        corrected: EvidenceId,
    },
}

impl std::fmt::Display for Unresolved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unresolved::NoRecords => formatter.write_str("the subject has no admitted records"),
            Unresolved::ForkedSuccession { prior } => write!(
                formatter,
                "record {prior:?} has more than one live successor"
            ),
            Unresolved::Cycle => formatter.write_str("supersession leads in a circle"),
            Unresolved::CompetingLiveRecords { live } => write!(
                formatter,
                "{} records are live and none supersedes the others: {live:?}",
                live.len()
            ),
            Unresolved::ConflictingCorrections { corrected } => write!(
                formatter,
                "record {corrected:?} carries conflicting corrections"
            ),
        }
    }
}

/// What the admitted evidence determines about a subject right now.
///
/// WHY this carries no identity, no digest, and no way to become evidence:
/// `docs/17-OBSERVABILITY_AND_EVIDENCE.md` requires the projection to be
/// neither new evidence nor a second authority. A projection that could be
/// digested and admitted would become a record about the subject, and the next
/// projection would read it -- at which point the derived view is an input to
/// itself and its provenance no longer reaches the observations underneath.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Projection {
    /// Exactly one record is current, with the corrections that amend it.
    Current {
        /// The live record.
        record: EvidenceId,
        /// Corrections amending it, from nearest to furthest.
        corrections: Vec<EvidenceId>,
    },
    /// The evidence does not determine a unique current record.
    Unresolved(Unresolved),
}

/// Project the current assessment of one subject.
///
/// The result is a function of the trusted records, the relations, and the
/// trusted delegations. It reads no clock and no ordering beyond the relations
/// themselves, so replaying the same inputs in any order yields the same value.
///
/// # Errors
///
/// Returns [`AssessmentError`] when the relation set itself cannot be admitted:
/// an unknown record or delegation, a cross-subject or self relation, a
/// duplicate relation identity, or an authority that did not hold the required
/// delegated action at the moment it asserted.
///
/// Time: O(r log r + n log n) for r relations over n records of the subject.
/// Space: O(r + n).
pub fn project(
    subject: &Digest,
    registry: &TrustedEvidenceRegistry,
    relations: &[AssessmentRelation],
    trusted_delegations: &BTreeMap<DelegationId, Delegation>,
) -> Result<Projection, AssessmentError> {
    let mut seen = BTreeSet::new();
    for relation in relations {
        if !seen.insert(&relation.id) {
            return Err(AssessmentError::DuplicateRelation {
                relation: relation.id.clone(),
            });
        }
        admit(relation, registry, trusted_delegations)?;
    }

    // Only relations whose records belong to this subject participate. A
    // relation about another subject is valid and simply not about this one.
    let mine: Vec<&AssessmentRelation> = relations
        .iter()
        .filter(|relation| {
            registry
                .resolve(&relation.prior)
                .is_some_and(|record| &record.subject == subject)
        })
        .collect();

    let records = subject_records(subject, registry, &mine);
    if records.is_empty() {
        return Ok(Projection::Unresolved(Unresolved::NoRecords));
    }

    let successors = edges(&mine, RelationKind::Supersession);
    for (prior, targets) in &successors {
        if targets.len() > 1 {
            return Ok(Projection::Unresolved(Unresolved::ForkedSuccession {
                prior: (*prior).clone(),
            }));
        }
    }

    let amendments = edges(&mine, RelationKind::Correction);
    // A record reached by a correction is an amendment of the record it
    // corrects, not a competing assessment of the subject. Counting it as live
    // would make every correction produce a fork -- the amendment has no
    // successor of its own, so it looks terminal from the supersession graph
    // alone.
    let amending: BTreeSet<&EvidenceId> = amendments.values().flatten().copied().collect();

    let live: Vec<EvidenceId> = records
        .iter()
        .filter(|record| !successors.contains_key(record) && !amending.contains(record))
        .cloned()
        .collect();

    // Every record superseding another, with nothing terminal, means the chain
    // closed on itself. Checked by absence of a live record rather than by
    // walking, because a graph in which every node has an outgoing edge and
    // finitely many nodes must contain a cycle.
    let Some(head) = live.first() else {
        return Ok(Projection::Unresolved(Unresolved::Cycle));
    };
    if live.len() > 1 {
        return Ok(Projection::Unresolved(Unresolved::CompetingLiveRecords {
            live,
        }));
    }

    let mut corrections = Vec::new();
    let mut at = head.clone();
    let mut visited = BTreeSet::new();
    while let Some(targets) = amendments.get(&at) {
        if targets.len() > 1 {
            return Ok(Projection::Unresolved(Unresolved::ConflictingCorrections {
                corrected: at,
            }));
        }
        // A correction chain that returns to a record it already amended is the
        // same defect as a supersession cycle, reached by the other edge kind.
        if !visited.insert(at.clone()) {
            return Ok(Projection::Unresolved(Unresolved::Cycle));
        }
        let Some(next) = targets.first() else { break };
        corrections.push((*next).clone());
        at = (*next).clone();
    }

    Ok(Projection::Current {
        record: head.clone(),
        corrections,
    })
}

/// Check one relation against the trusted registries.
fn admit(
    relation: &AssessmentRelation,
    registry: &TrustedEvidenceRegistry,
    trusted_delegations: &BTreeMap<DelegationId, Delegation>,
) -> Result<(), AssessmentError> {
    if relation.prior == relation.successor {
        return Err(AssessmentError::SelfRelation {
            relation: relation.id.clone(),
        });
    }

    let prior = resolve(registry, relation, &relation.prior)?;
    let successor = resolve(registry, relation, &relation.successor)?;
    if prior.subject != successor.subject {
        return Err(AssessmentError::CrossSubject {
            relation: relation.id.clone(),
        });
    }

    let Some(delegation) = trusted_delegations.get(&relation.authority_delegation) else {
        return Err(AssessmentError::UnknownAuthority {
            relation: relation.id.clone(),
            delegation: relation.authority_delegation.clone(),
        });
    };
    if delegation.subject != relation.authority {
        return Err(AssessmentError::AuthorityMismatch {
            relation: relation.id.clone(),
        });
    }
    let action = relation.kind.required_action();
    if !delegation.actions.contains(action) {
        return Err(AssessmentError::ActionNotDelegated {
            relation: relation.id.clone(),
            action,
        });
    }
    // Checked against the moment of assertion rather than a call-time clock:
    // whether the authority held then is a fact that does not change later, and
    // reading a clock here would make the projection depend on when it ran.
    if delegation.is_expired(relation.asserted_at) {
        return Err(AssessmentError::StaleAuthority {
            relation: relation.id.clone(),
        });
    }
    Ok(())
}

fn resolve<'registry>(
    registry: &'registry TrustedEvidenceRegistry,
    relation: &AssessmentRelation,
    id: &EvidenceId,
) -> Result<&'registry EvidenceRecord, AssessmentError> {
    registry
        .resolve(id)
        .ok_or_else(|| AssessmentError::UnknownRecord {
            relation: relation.id.clone(),
            record: id.clone(),
        })
}

/// Every record of this subject that a relation names.
///
/// WHY derived from the relations rather than by scanning the registry: the
/// registry holds every admitted record for every subject and offers no
/// subject index, and a projection over records nothing relates would report
/// `CompetingLiveRecords` for any subject observed twice, which is a fact about
/// the registry's contents rather than about the relations under test.
fn subject_records(
    subject: &Digest,
    registry: &TrustedEvidenceRegistry,
    relations: &[&AssessmentRelation],
) -> BTreeSet<EvidenceId> {
    let mut records = BTreeSet::new();
    for relation in relations {
        for id in [&relation.prior, &relation.successor] {
            if registry
                .resolve(id)
                .is_some_and(|record| &record.subject == subject)
            {
                records.insert(id.clone());
            }
        }
    }
    records
}

/// Outgoing edges of one kind, keyed by the record they leave.
fn edges<'relation>(
    relations: &[&'relation AssessmentRelation],
    kind: RelationKind,
) -> BTreeMap<EvidenceId, Vec<&'relation EvidenceId>> {
    let mut map: BTreeMap<EvidenceId, Vec<&EvidenceId>> = BTreeMap::new();
    for relation in relations.iter().filter(|relation| relation.kind == kind) {
        map.entry(relation.prior.clone())
            .or_default()
            .push(&relation.successor);
    }
    map
}
