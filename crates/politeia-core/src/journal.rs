//! The transition journal: an append-only record of accepted state changes.
//!
//! `docs/09-PERSISTENCE.md` asks for a normalized state model *plus* immutable
//! journals, and lists what every consequential entry binds — actor,
//! delegation, operation, before/after identity, policy, runtime, execution
//! resource and routing decision, adapter, evidence, timestamp, and chain
//! metadata.
//!
//! The bindings are required fields rather than an encouraged convention.
//! `politeia_core::state` answers *what is true now*; this answers *how it came
//! to be*, and an entry missing its authority answers neither — it records that
//! something changed without recording that anyone was allowed to change it.
//!
//! WHY the chain is computed here and not supplied: an entry whose caller fills
//! in its own predecessor is an entry whose caller can fill in the wrong one,
//! and the resulting journal verifies against itself perfectly. The journal
//! links each entry to the one it actually followed.

use std::collections::BTreeSet;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::institution::{InstitutionBoundary, TrustDomainId, WorkspaceScoped};
use crate::{
    AdapterId, DelegationId, Digest, DigestDomain, EvidenceId, ExecutionResourceId,
    InstitutionWorkspaceId, OperationId, PolicyBundleId, PrincipalId, RoutingDecisionId,
    RuntimeGenerationId, canonical::CanonicalError,
};

/// One accepted state transition, with everything it binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionEntry {
    /// The workspace whose state changed.
    pub workspace: InstitutionWorkspaceId,
    /// The trust domain the record belongs to.
    pub trust_domain: TrustDomainId,
    /// The principal that made the change.
    pub actor: PrincipalId,
    /// The exact delegation it acted under.
    pub delegation: DelegationId,
    /// The semantic operation performed.
    pub operation: OperationId,
    /// Digest of the state before, where there was one.
    pub before: Option<Digest>,
    /// Digest of the state after, where there is one.
    pub after: Option<Digest>,
    /// The policy bundle in force.
    pub policy_bundle: PolicyBundleId,
    /// Digest of the exact policy bundle bytes.
    pub policy_digest: Digest,
    /// The runtime generation that was running.
    pub runtime: RuntimeGenerationId,
    /// The execution resource involved, where one was.
    pub execution_resource: Option<ExecutionResourceId>,
    /// The routing decision that selected it, where one did.
    pub routing_decision: Option<RoutingDecisionId>,
    /// The adapter involved, where one was.
    pub adapter: Option<AdapterId>,
    /// Evidence produced or cited by the transition.
    pub evidence: BTreeSet<EvidenceId>,
    /// When it was accepted.
    pub at: Timestamp,
}

impl WorkspaceScoped for TransitionEntry {
    fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }
}

/// An entry as it sits in the journal, linked to the one before it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ChainedEntry {
    entry: TransitionEntry,
    previous: Option<Digest>,
    digest: Digest,
}

impl ChainedEntry {
    /// What was recorded.
    pub fn entry(&self) -> &TransitionEntry {
        &self.entry
    }

    /// The digest of the entry before this one, if any.
    pub fn previous(&self) -> Option<&Digest> {
        self.previous.as_ref()
    }

    /// This entry's own digest, over its content and its predecessor.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Serialize)]
struct Linked<'a> {
    previous: Option<&'a Digest>,
    entry: &'a TransitionEntry,
}

fn link_digest(
    previous: Option<&Digest>,
    entry: &TransitionEntry,
) -> Result<Digest, CanonicalError> {
    Digest::of(
        DigestDomain::TransitionJournalEntry,
        &Linked { previous, entry },
    )
}

/// Why an entry could not be appended.
///
/// `Debug` only, like the crate's other errors that carry a
/// [`CanonicalError`]: that type wraps a `serde_json::Error`, which is neither
/// `Clone` nor `Eq`, and deriving those here would mean either dropping the
/// source or wrapping it in something that loses it.
#[derive(Debug)]
#[non_exhaustive]
pub enum AppendRefusal {
    /// The entry belongs to another institution.
    ForeignWorkspace {
        /// The workspace the entry names.
        workspace: InstitutionWorkspaceId,
    },
    /// The entry could not be encoded canonically.
    Encoding(CanonicalError),
}

impl std::fmt::Display for AppendRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendRefusal::ForeignWorkspace { workspace } => write!(
                formatter,
                "the entry belongs to workspace {workspace:?}, not this journal's"
            ),
            AppendRefusal::Encoding(error) => {
                write!(formatter, "the entry cannot be journalled: {error}")
            }
        }
    }
}

impl std::error::Error for AppendRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppendRefusal::ForeignWorkspace { .. } => None,
            AppendRefusal::Encoding(error) => Some(error),
        }
    }
}

/// Where a chain stops holding together.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainBreak {
    /// An entry's recorded digest is not the digest of its content.
    ///
    /// This is what an altered entry looks like: the content moved and the
    /// digest beside it did not.
    ContentAltered {
        /// Position of the entry in the journal.
        at: usize,
    },
    /// An entry does not follow the one before it.
    ///
    /// This is what a removed or reordered entry looks like — the links still
    /// verify individually and no longer form one sequence.
    LinkBroken {
        /// Position of the entry whose predecessor does not match.
        at: usize,
    },
    /// An entry could not be re-encoded for checking.
    Unverifiable {
        /// Position of the entry.
        at: usize,
    },
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainBreak::ContentAltered { at } => {
                write!(formatter, "entry {at} does not match its recorded digest")
            }
            ChainBreak::LinkBroken { at } => {
                write!(formatter, "entry {at} does not follow the entry before it")
            }
            ChainBreak::Unverifiable { at } => {
                write!(formatter, "entry {at} cannot be re-encoded for checking")
            }
        }
    }
}

impl std::error::Error for ChainBreak {}

/// Check that a sequence of entries forms one unbroken chain.
///
/// WHY this takes a slice rather than being a method on the journal: a check
/// that can only be run over a journal the journal itself built can only ever
/// be shown passing. Taking the sequence means a tampered one can be handed to
/// it, which is the only way to know it reports what it claims to.
///
/// # Errors
///
/// Returns the first [`ChainBreak`]: an entry whose content no longer matches
/// its digest, one that does not follow its predecessor, or one that cannot be
/// re-encoded.
///
/// Time: O(n) encodings. Space: O(1).
pub fn verify_chain(entries: &[ChainedEntry]) -> Result<(), ChainBreak> {
    let mut expected: Option<&Digest> = None;
    for (at, chained) in entries.iter().enumerate() {
        if chained.previous.as_ref() != expected {
            return Err(ChainBreak::LinkBroken { at });
        }
        let recomputed = link_digest(chained.previous.as_ref(), &chained.entry)
            .map_err(|_| ChainBreak::Unverifiable { at })?;
        if recomputed != chained.digest {
            return Err(ChainBreak::ContentAltered { at });
        }
        expected = Some(&chained.digest);
    }
    Ok(())
}

/// An append-only record of one institution's accepted transitions.
///
/// There is no removal, no replacement, and no mutable access to what is
/// already recorded. `docs/02-CONSTITUTION.md` law 12 requires corrections to
/// append rather than rewrite, and a journal offering a way to rewrite is a
/// journal that will be rewritten.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionJournal {
    workspace: InstitutionWorkspaceId,
    entries: Vec<ChainedEntry>,
}

impl TransitionJournal {
    /// Open a journal for the institution a boundary is scoped to.
    pub fn for_boundary<Outbox>(boundary: &InstitutionBoundary<Outbox>) -> Self {
        Self {
            workspace: boundary.workspace().clone(),
            entries: Vec::new(),
        }
    }

    /// The institution this journal records.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Everything recorded, oldest first.
    pub fn entries(&self) -> &[ChainedEntry] {
        &self.entries
    }

    /// The digest of the most recent entry, which the next one will bind.
    pub fn head(&self) -> Option<&Digest> {
        self.entries.last().map(ChainedEntry::digest)
    }

    /// Record one accepted transition.
    ///
    /// # Errors
    ///
    /// Returns [`AppendRefusal`] when the entry belongs to another institution
    /// or cannot be encoded canonically.
    ///
    /// Time: O(1) amortised plus one encoding. Space: O(1) amortised.
    pub fn append(&mut self, entry: TransitionEntry) -> Result<&ChainedEntry, AppendRefusal> {
        if entry.workspace != self.workspace {
            return Err(AppendRefusal::ForeignWorkspace {
                workspace: entry.workspace,
            });
        }
        let previous = self.head().cloned();
        let digest = link_digest(previous.as_ref(), &entry).map_err(AppendRefusal::Encoding)?;
        self.entries.push(ChainedEntry {
            entry,
            previous,
            digest,
        });
        // INVARIANT: just pushed, so the journal is non-empty.
        Ok(self
            .entries
            .last()
            .unwrap_or_else(|| unreachable!("an entry was just appended")))
    }

    /// Check that nothing recorded has been altered or removed.
    ///
    /// # Errors
    ///
    /// Returns the first [`ChainBreak`] found.
    pub fn verify(&self) -> Result<(), ChainBreak> {
        verify_chain(&self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstitutionId;

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed values cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose trust domain is not canonical is a broken test"
    )]
    fn trust_domain() -> TrustDomainId {
        "client-a:production"
            .parse()
            .expect("the fixture trust domain is canonical")
    }

    fn boundary() -> InstitutionBoundary<()> {
        InstitutionBoundary::new(InstitutionId::new(), InstitutionWorkspaceId::new(), ())
    }

    fn entry(workspace: &InstitutionWorkspaceId, after: &[u8]) -> TransitionEntry {
        TransitionEntry {
            workspace: workspace.clone(),
            trust_domain: trust_domain(),
            actor: PrincipalId::new(),
            delegation: DelegationId::new(),
            operation: OperationId::new(),
            before: None,
            after: Some(Digest::blake3(after)),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            runtime: RuntimeGenerationId::derive(b"generation"),
            execution_resource: None,
            routing_decision: None,
            adapter: None,
            evidence: BTreeSet::new(),
            at: now(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot append is a broken test, not a finding"
    )]
    fn journal_of(b: &InstitutionBoundary<()>, count: usize) -> TransitionJournal {
        let mut journal = TransitionJournal::for_boundary(b);
        for index in 0..count {
            journal
                .append(entry(b.workspace(), format!("state {index}").as_bytes()))
                .expect("the fixture entry appends");
        }
        journal
    }

    #[test]
    fn each_entry_binds_the_one_before_it() {
        let b = boundary();
        let journal = journal_of(&b, 3);
        let entries = journal.entries();

        assert_eq!(entries[0].previous(), None, "the first binds nothing");
        assert_eq!(entries[1].previous(), Some(entries[0].digest()));
        assert_eq!(entries[2].previous(), Some(entries[1].digest()));
        assert_eq!(journal.head(), Some(entries[2].digest()));
        assert_eq!(journal.verify(), Ok(()));
    }

    #[test]
    fn an_altered_entry_is_caught() {
        // The property the chain exists for, shown failing. Content moved and
        // the digest beside it did not.
        let b = boundary();
        let journal = journal_of(&b, 3);
        let mut tampered = journal.entries().to_vec();
        tampered[1].entry.after = Some(Digest::blake3(b"something else entirely"));

        assert_eq!(
            verify_chain(&tampered),
            Err(ChainBreak::ContentAltered { at: 1 }),
            "the break must name where it is, not merely that there is one"
        );
    }

    #[test]
    fn a_removed_entry_is_caught() {
        // Every remaining entry still matches its own digest -- individually
        // they all verify. What no longer holds is that they form one sequence.
        let b = boundary();
        let journal = journal_of(&b, 3);
        let mut shortened = journal.entries().to_vec();
        shortened.remove(1);

        assert_eq!(
            verify_chain(&shortened),
            Err(ChainBreak::LinkBroken { at: 1 })
        );
    }

    #[test]
    fn a_reordered_pair_is_caught() {
        let b = boundary();
        let journal = journal_of(&b, 3);
        let mut swapped = journal.entries().to_vec();
        swapped.swap(1, 2);

        assert_eq!(
            verify_chain(&swapped),
            Err(ChainBreak::LinkBroken { at: 1 })
        );
    }

    #[test]
    fn an_empty_journal_verifies() {
        // Vacuously, and that is correct: nothing recorded is nothing to
        // contradict. Stated because a chain check that failed on empty would
        // make every fresh journal look corrupt.
        let b = boundary();
        assert_eq!(TransitionJournal::for_boundary(&b).verify(), Ok(()));
        assert_eq!(verify_chain(&[]), Ok(()));
    }

    #[test]
    fn an_entry_from_another_institution_is_refused() {
        let b = boundary();
        let mut journal = TransitionJournal::for_boundary(&b);
        let theirs = InstitutionWorkspaceId::new();

        let refused = journal.append(entry(&theirs, b"their state"));
        assert!(matches!(
            refused,
            Err(AppendRefusal::ForeignWorkspace { .. })
        ));
        assert!(
            journal.entries().is_empty(),
            "a refused append must leave the journal untouched"
        );
    }

    #[test]
    fn two_journals_over_the_same_entries_agree() {
        // The digest covers content and predecessor and nothing else -- no
        // clock, no counter, no insertion order beyond the chain itself. Two
        // journals fed the same entries produce the same chain, which is what
        // makes an independent verifier possible.
        let b = boundary();
        let one = entry(b.workspace(), b"first");
        let two = entry(b.workspace(), b"second");

        let mut left = TransitionJournal::for_boundary(&b);
        let mut right = TransitionJournal::for_boundary(&b);
        for journal in [&mut left, &mut right] {
            assert!(journal.append(one.clone()).is_ok());
            assert!(journal.append(two.clone()).is_ok());
        }
        assert_eq!(left.head(), right.head());
        assert_eq!(left.entries(), right.entries());
    }

    #[test]
    fn every_break_variant_names_the_test_that_reaches_it() {
        // `Unverifiable` has no test: it needs an entry that encodes on append
        // and fails to re-encode afterwards, which nothing in this type can
        // produce -- the entry is immutable once recorded. It is kept because
        // `link_digest` is fallible and swallowing that would be worse, and
        // this comment is the record that it is unreached rather than
        // forgotten.
        let reached_by = |break_: &ChainBreak| -> &'static str {
            match break_ {
                ChainBreak::ContentAltered { .. } => "an_altered_entry_is_caught",
                ChainBreak::LinkBroken { .. } => "a_removed_entry_is_caught",
                ChainBreak::Unverifiable { .. } => "(unreachable; see the comment above)",
            }
        };
        assert_eq!(
            reached_by(&ChainBreak::ContentAltered { at: 0 }),
            "an_altered_entry_is_caught"
        );
    }
}
