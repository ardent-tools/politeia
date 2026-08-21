//! Institutional knowledge: what was observed, what it is taken to mean, and
//! what has to be true before either becomes a fact.
//!
//! `docs/03-ONTOLOGY.md` separates three things that a system without types
//! runs together: an `Observation` is a sourced statement about reality, a
//! `Claim` is an interpreted proposition with confidence and provenance, and an
//! `ApprovedFact` is what the institution has accepted. The interpretation step
//! is where a source's word becomes the institution's, and it is the step worth
//! making visible.
//!
//! WHY contestedness is derived rather than declared: a `contested: bool` is a
//! field, and a field can be wrong or simply never set. Reading it off the
//! observations means a contradiction cannot be dropped by omission --
//! `docs/18-FIRST_VERTICAL_SLICE.md` requires that contradictions *remain
//! visible until approved*, and a claim that computes its own status is how
//! that survives someone forgetting.
//!
//! The same reasoning applies to support. A declared confidence is a number
//! nothing can contradict; [`Support`] is read off how many distinct sources
//! observed the thing, which is a fact about the evidence rather than about the
//! interpreter's mood.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdapterId, ClaimId, DelegationId, Digest, EvidenceId, InstitutionWorkspaceId, ObservationId,
    PrincipalId,
};

/// A sourced statement about reality.
///
/// Every field answers "how do you know", and none of them is the statement's
/// meaning: an observation records that a named source, reached through an
/// exact adapter, said a particular thing at a particular time. What it is
/// taken to mean is a [`CandidateClaim`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// This observation's identity.
    pub id: ObservationId,
    /// The workspace that owns the observation.
    ///
    /// WHY an observation names its workspace: institutional facts are
    /// client-owned, and `docs/16-DATA_GOVERNANCE.md` requires an explicit
    /// authorized export before one institution's material is reused by
    /// another. Without this field a cross-institution observation is
    /// structurally indistinguishable from a local one, and the quarantine
    /// `docs/11-FAILURE_SEMANTICS.md` requires has nothing to key on.
    pub workspace: InstitutionWorkspaceId,
    /// The source the statement came from, as the institution names it.
    pub source: String,
    /// The exact adapter that reached the source.
    pub adapter: AdapterId,
    /// Digest of the subject the statement is about.
    pub subject: Digest,
    /// Digest of the statement itself.
    pub statement: Digest,
    /// Trusted time the observation was admitted.
    pub observed_at: Timestamp,
    /// The admitted evidence record backing it.
    pub evidence: EvidenceId,
}

/// How well-supported a claim is, read off its observations.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Nothing observed it.
    None,
    /// One source observed it.
    Single,
    /// Two or more distinct sources observed it.
    ///
    /// Counted by source rather than by observation: one source polled twice
    /// has said one thing twice, and treating that as corroboration is how a
    /// single unreliable source becomes a consensus.
    Corroborated,
}

/// Where a claim stands before anyone approves it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// No observation supports it.
    Unsupported,
    /// At least one observation contradicts it.
    ///
    /// Contradiction outranks support: a claim with nine supporting
    /// observations and one contradicting one is contested, not
    /// nine-tenths true.
    Contested,
    /// Supported, uncontradicted, and not yet approved.
    Candidate,
}

/// An interpreted proposition, with the observations behind and against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaim {
    /// This claim's identity.
    pub id: ClaimId,
    /// Digest of the subject the proposition is about.
    pub subject: Digest,
    /// Digest of the proposition.
    pub proposition: Digest,
    /// Observations that support it, by the source that made each.
    pub supported_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Observations that contradict it, by the source that made each.
    pub contradicted_by: BTreeMap<String, BTreeSet<ObservationId>>,
    /// Axes the reconnaissance that produced this claim did not cover.
    ///
    /// Declared by the interpreter, because only it knows what it did not look
    /// at. An empty set is a claim that nothing was missed, which is a
    /// statement rather than a default -- and one an approver has to accept.
    pub missed_axes: BTreeSet<String>,
    /// The principal that interpreted the observations.
    pub interpreter: PrincipalId,
    /// The exact delegation it interpreted under.
    pub interpreter_delegation: DelegationId,
}

impl CandidateClaim {
    /// How well-supported the claim is.
    pub fn support(&self) -> Support {
        match self.supported_by.len() {
            0 => Support::None,
            1 => Support::Single,
            _ => Support::Corroborated,
        }
    }

    /// Where the claim stands.
    pub fn status(&self) -> ClaimStatus {
        if !self.contradicted_by.is_empty() {
            ClaimStatus::Contested
        } else if self.supported_by.is_empty() {
            ClaimStatus::Unsupported
        } else {
            ClaimStatus::Candidate
        }
    }
}

/// An institution owner's acceptance of one claim.
///
/// It restates what it is accepting rather than pointing at it. That is
/// deliberate: an approval that carried only a claim identity would still be
/// valid after the claim gained a contradiction, and the approver would have
/// accepted something they never saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactApproval {
    /// The claim being accepted.
    pub claim: ClaimId,
    /// The proposition as the approver saw it.
    pub proposition: Digest,
    /// The status the approver saw.
    pub acknowledged_status: ClaimStatus,
    /// The gaps the approver saw and accepted.
    pub acknowledged_missed_axes: BTreeSet<String>,
    /// The institution owner accepting it.
    pub owner: PrincipalId,
    /// The exact delegation carrying that authority.
    pub owner_delegation: DelegationId,
    /// When the approval was given.
    pub approved_at: Timestamp,
}

/// Why a claim did not become an approved fact.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalRefusal {
    /// The approval names a different claim.
    WrongClaim {
        /// The claim presented.
        claim: ClaimId,
        /// The claim the approval names.
        approved: ClaimId,
    },
    /// The proposition changed after the approval was given.
    PropositionChanged,
    /// The claim is contradicted and no owner may approve it as it stands.
    ///
    /// The contradiction has to be resolved -- by evidence, by a correction, or
    /// by withdrawing the claim -- rather than approved past.
    /// `docs/18-FIRST_VERTICAL_SLICE.md`: contradictions remain visible until
    /// approved, and this is what "remain visible" means when someone tries to
    /// approve anyway.
    Contested {
        /// The sources that contradict it.
        sources: BTreeSet<String>,
    },
    /// Nothing observed the claim.
    Unsupported,
    /// The approver saw a different status than the claim now has.
    StatusChanged {
        /// What the approver acknowledged.
        acknowledged: ClaimStatus,
        /// What the claim is now.
        actual: ClaimStatus,
    },
    /// The claim declares gaps the approval does not acknowledge.
    UnacknowledgedGaps {
        /// The axes declared and not acknowledged.
        missed: BTreeSet<String>,
    },
}

impl std::fmt::Display for ApprovalRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalRefusal::WrongClaim { claim, approved } => write!(
                formatter,
                "approval names {approved:?}, not the claim {claim:?} presented"
            ),
            ApprovalRefusal::PropositionChanged => {
                formatter.write_str("the proposition changed after the approval was given")
            }
            ApprovalRefusal::Contested { sources } => write!(
                formatter,
                "the claim is contradicted by {sources:?} and cannot be approved as it stands"
            ),
            ApprovalRefusal::Unsupported => {
                formatter.write_str("no observation supports the claim")
            }
            ApprovalRefusal::StatusChanged {
                acknowledged,
                actual,
            } => write!(
                formatter,
                "the approver saw {acknowledged:?}; the claim is now {actual:?}"
            ),
            ApprovalRefusal::UnacknowledgedGaps { missed } => write!(
                formatter,
                "the claim declares gaps the approval does not acknowledge: {missed:?}"
            ),
        }
    }
}

impl std::error::Error for ApprovalRefusal {}

/// A claim the institution has accepted.
///
/// Constructible only through [`approve`], so the checks are not something a
/// caller can route around by building the value directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApprovedFact {
    claim: ClaimId,
    subject: Digest,
    proposition: Digest,
    support: Support,
    accepted_gaps: BTreeSet<String>,
    owner: PrincipalId,
    approved_at: Timestamp,
}

impl ApprovedFact {
    /// The claim this fact came from.
    pub fn claim(&self) -> &ClaimId {
        &self.claim
    }
    /// The subject the fact is about.
    pub fn subject(&self) -> &Digest {
        &self.subject
    }
    /// The proposition accepted.
    pub fn proposition(&self) -> &Digest {
        &self.proposition
    }
    /// How well-supported it was when accepted.
    pub fn support(&self) -> Support {
        self.support
    }
    /// The gaps the owner accepted along with it.
    ///
    /// Carried forward rather than discarded: a fact approved with known gaps
    /// is a different thing from one approved without, and a consumer that
    /// cannot tell them apart will treat them alike.
    pub fn accepted_gaps(&self) -> &BTreeSet<String> {
        &self.accepted_gaps
    }
    /// The institution owner that accepted it.
    pub fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    /// When it was accepted.
    pub fn approved_at(&self) -> Timestamp {
        self.approved_at
    }
}

/// Accept a claim as an institutional fact.
///
/// # Errors
///
/// Returns [`ApprovalRefusal`] when the approval does not match the claim it
/// names, when the claim is contested or unsupported, when its status has moved
/// since the approver saw it, or when it declares gaps the approval does not
/// acknowledge.
///
/// Time: O(g) for g declared gaps. Space: O(g).
pub fn approve(
    claim: &CandidateClaim,
    approval: &FactApproval,
) -> Result<ApprovedFact, ApprovalRefusal> {
    if approval.claim != claim.id {
        return Err(ApprovalRefusal::WrongClaim {
            claim: claim.id.clone(),
            approved: approval.claim.clone(),
        });
    }
    if approval.proposition != claim.proposition {
        return Err(ApprovalRefusal::PropositionChanged);
    }

    let status = claim.status();
    if approval.acknowledged_status != status {
        return Err(ApprovalRefusal::StatusChanged {
            acknowledged: approval.acknowledged_status,
            actual: status,
        });
    }
    match status {
        ClaimStatus::Contested => {
            return Err(ApprovalRefusal::Contested {
                sources: claim.contradicted_by.keys().cloned().collect(),
            });
        }
        ClaimStatus::Unsupported => return Err(ApprovalRefusal::Unsupported),
        ClaimStatus::Candidate => {}
    }

    // Set difference rather than equality: acknowledging a gap the claim does
    // not declare is harmless caution, while failing to acknowledge one it does
    // declare is the approver not having seen it.
    let unacknowledged: BTreeSet<String> = claim
        .missed_axes
        .difference(&approval.acknowledged_missed_axes)
        .cloned()
        .collect();
    if !unacknowledged.is_empty() {
        return Err(ApprovalRefusal::UnacknowledgedGaps {
            missed: unacknowledged,
        });
    }

    Ok(ApprovedFact {
        claim: claim.id.clone(),
        subject: claim.subject.clone(),
        proposition: claim.proposition.clone(),
        support: claim.support(),
        accepted_gaps: claim.missed_axes.clone(),
        owner: approval.owner.clone(),
        approved_at: approval.approved_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    fn subject() -> Digest {
        Digest::blake3(b"the institution's billing contact")
    }

    fn proposition() -> Digest {
        Digest::blake3(b"billing is handled by the finance team")
    }

    fn observation(source: &str) -> Observation {
        Observation {
            id: ObservationId::new(),
            workspace: InstitutionWorkspaceId::new(),
            source: source.to_string(),
            adapter: AdapterId::new(),
            subject: subject(),
            statement: Digest::blake3(source.as_bytes()),
            observed_at: now(),
            evidence: EvidenceId::new(),
        }
    }

    fn by_source(observations: &[&Observation]) -> BTreeMap<String, BTreeSet<ObservationId>> {
        let mut map: BTreeMap<String, BTreeSet<ObservationId>> = BTreeMap::new();
        for observation in observations {
            map.entry(observation.source.clone())
                .or_default()
                .insert(observation.id.clone());
        }
        map
    }

    fn claim(
        supported: &[&Observation],
        contradicted: &[&Observation],
        missed: &[&str],
    ) -> CandidateClaim {
        CandidateClaim {
            id: ClaimId::new(),
            subject: subject(),
            proposition: proposition(),
            supported_by: by_source(supported),
            contradicted_by: by_source(contradicted),
            missed_axes: missed.iter().map(|axis| (*axis).to_string()).collect(),
            interpreter: PrincipalId::new(),
            interpreter_delegation: DelegationId::new(),
        }
    }

    fn approval(claim: &CandidateClaim, acknowledged: &[&str]) -> FactApproval {
        FactApproval {
            claim: claim.id.clone(),
            proposition: claim.proposition.clone(),
            acknowledged_status: claim.status(),
            acknowledged_missed_axes: acknowledged.iter().map(|a| (*a).to_string()).collect(),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_at: now(),
        }
    }

    #[test]
    fn one_source_is_support_and_two_are_corroboration() {
        let first = observation("crm");
        let second = observation("payroll");
        assert_eq!(claim(&[], &[], &[]).support(), Support::None);
        assert_eq!(claim(&[&first], &[], &[]).support(), Support::Single);
        assert_eq!(
            claim(&[&first, &second], &[], &[]).support(),
            Support::Corroborated
        );
    }

    #[test]
    fn one_source_polled_twice_is_not_corroboration() {
        // The distinction the map keys exist for. Counting observations rather
        // than sources is how a single unreliable source becomes a consensus
        // by being asked again.
        let once = observation("crm");
        let twice = Observation {
            id: ObservationId::new(),
            ..once.clone()
        };
        assert_eq!(claim(&[&once, &twice], &[], &[]).support(), Support::Single);
    }

    #[test]
    fn a_contradiction_outranks_any_amount_of_support() {
        // Nine to one is contested, not nine-tenths true.
        let supporting: Vec<Observation> = (0..9)
            .map(|index| observation(&format!("source-{index}")))
            .collect();
        let against = observation("ledger");
        let refs: Vec<&Observation> = supporting.iter().collect();
        let contested = claim(&refs, &[&against], &[]);

        assert_eq!(contested.support(), Support::Corroborated);
        assert_eq!(contested.status(), ClaimStatus::Contested);
    }

    #[test]
    fn an_unobserved_claim_is_unsupported_rather_than_merely_unapproved() {
        assert_eq!(claim(&[], &[], &[]).status(), ClaimStatus::Unsupported);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not approve is a broken test, not a finding"
    )]
    fn a_supported_uncontradicted_claim_is_approvable() {
        let seen = observation("crm");
        let candidate = claim(&[&seen], &[], &[]);
        let accepted = approve(&candidate, &approval(&candidate, &[]));

        let fact = accepted.as_ref().expect("a clean candidate is approvable");
        assert_eq!(fact.claim(), &candidate.id);
        assert_eq!(fact.proposition(), &proposition());
        assert_eq!(fact.support(), Support::Single);
        assert!(fact.accepted_gaps().is_empty());
    }

    #[test]
    fn a_contested_claim_cannot_be_approved_past() {
        // `docs/18-FIRST_VERTICAL_SLICE.md`: contradictions remain visible
        // until approved. This is what "remain visible" means when someone
        // tries to approve anyway -- the contradiction is not a warning the
        // approver can accept, it is a refusal.
        let seen = observation("crm");
        let against = observation("ledger");
        let contested = claim(&[&seen], &[&against], &[]);

        assert_eq!(
            approve(&contested, &approval(&contested, &[])),
            Err(ApprovalRefusal::Contested {
                sources: BTreeSet::from(["ledger".to_string()]),
            })
        );
    }

    #[test]
    fn an_unsupported_claim_cannot_be_approved() {
        let empty = claim(&[], &[], &[]);
        assert_eq!(
            approve(&empty, &approval(&empty, &[])),
            Err(ApprovalRefusal::Unsupported)
        );
    }

    #[test]
    fn a_gap_the_approval_does_not_acknowledge_refuses() {
        let seen = observation("crm");
        let candidate = claim(&[&seen], &[], &["subsidiaries", "historical contracts"]);

        assert_eq!(
            approve(&candidate, &approval(&candidate, &["subsidiaries"])),
            Err(ApprovalRefusal::UnacknowledgedGaps {
                missed: BTreeSet::from(["historical contracts".to_string()]),
            }),
            "an approver who saw one gap has not accepted the other"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not approve is a broken test, not a finding"
    )]
    fn acknowledging_every_gap_approves_and_carries_them_forward() {
        // A fact approved with known gaps is a different thing from one
        // approved without, and a consumer that cannot tell them apart will
        // treat them alike.
        let seen = observation("crm");
        let candidate = claim(&[&seen], &[], &["subsidiaries", "historical contracts"]);
        let accepted = approve(
            &candidate,
            &approval(&candidate, &["subsidiaries", "historical contracts"]),
        );

        let fact = accepted.as_ref().expect("every declared gap was accepted");
        assert_eq!(
            fact.accepted_gaps(),
            &BTreeSet::from([
                "historical contracts".to_string(),
                "subsidiaries".to_string()
            ])
        );
    }

    #[test]
    fn acknowledging_a_gap_the_claim_does_not_declare_is_harmless() {
        let seen = observation("crm");
        let candidate = claim(&[&seen], &[], &["subsidiaries"]);
        assert!(
            approve(
                &candidate,
                &approval(&candidate, &["subsidiaries", "something else entirely"])
            )
            .is_ok(),
            "extra caution is not a defect"
        );
    }

    #[test]
    fn an_approval_for_another_claim_is_refused() {
        let seen = observation("crm");
        let mine = claim(&[&seen], &[], &[]);
        let theirs = claim(&[&seen], &[], &[]);
        assert_eq!(
            approve(&mine, &approval(&theirs, &[])),
            Err(ApprovalRefusal::WrongClaim {
                claim: mine.id.clone(),
                approved: theirs.id.clone(),
            })
        );
    }

    #[test]
    fn a_proposition_that_changed_after_approval_is_refused() {
        // The reason the approval restates what it accepted instead of naming
        // it. Carrying only an identity would leave the approval valid over
        // whatever the claim later said.
        let seen = observation("crm");
        let mut candidate = claim(&[&seen], &[], &[]);
        let given = approval(&candidate, &[]);
        candidate.proposition = Digest::blake3(b"something the owner never read");

        assert_eq!(
            approve(&candidate, &given),
            Err(ApprovalRefusal::PropositionChanged)
        );
    }

    #[test]
    fn a_claim_that_gained_a_contradiction_after_approval_is_refused() {
        // The race the acknowledged status exists for: the owner approved a
        // clean candidate, and a contradicting observation arrived before the
        // approval was applied.
        let seen = observation("crm");
        let candidate = claim(&[&seen], &[], &[]);
        let given = approval(&candidate, &[]);

        let against = observation("ledger");
        let contested = CandidateClaim {
            contradicted_by: by_source(&[&against]),
            ..candidate
        };

        assert_eq!(
            approve(&contested, &given),
            Err(ApprovalRefusal::StatusChanged {
                acknowledged: ClaimStatus::Candidate,
                actual: ClaimStatus::Contested,
            }),
            "the refusal must name the change, not merely the contradiction"
        );
    }
}
