//! Ordinary operational state, scoped to one institution.
//!
//! `docs/09-PERSISTENCE.md` draws a line this module sits on one side of:
//!
//! > Use assessment events where changing interpretation and its provenance
//! > matter [...] Keep ordinary normalized state where replaying history adds
//! > no value.
//!
//! So state here is mutable, and that is the point of it being separate from
//! evidence. An evidence record is immutable and corrected by appending; a
//! state entry is the current value of something and is meant to be replaced.
//! Writing replaces, and returns what was replaced so a caller who needs the
//! prior value has it rather than having to have kept one.
//!
//! WHY an entry holds a digest rather than a value: `docs/16-DATA_GOVERNANCE.md`
//! requires ordinary context to carry secret references or credential
//! identities where possible, not raw secret values. Making the field a
//! [`Digest`] means a secret cannot come to rest here by accident -- there is
//! nowhere to put it. That is a stronger guarantee than a rule saying not to,
//! and it costs a lookup.
//!
//! LIMIT, because a store invites the assumption: nothing here models
//! concurrency or write ordering. Two writers racing for one key is a question
//! this type does not answer, and a caller that needs it answered needs a
//! durable store with its own concurrency contract rather than this.

use std::collections::BTreeMap;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::institution::{InstitutionBoundary, WorkspaceScoped};
use crate::{DelegationId, Digest, InstitutionWorkspaceId, PrincipalId};

/// One named piece of an institution's current state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateEntry {
    /// The workspace this belongs to.
    pub workspace: InstitutionWorkspaceId,
    /// What it is called.
    pub key: String,
    /// Digest of the value, never the value.
    pub value: Digest,
    /// When it was written.
    pub written_at: Timestamp,
    /// The principal answering for the write.
    pub authority: PrincipalId,
    /// The exact delegation carrying that authority.
    pub authority_delegation: DelegationId,
}

impl WorkspaceScoped for StateEntry {
    fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }
}

/// Why a write was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateRefusal {
    /// The entry belongs to another workspace.
    ForeignWorkspace {
        /// The workspace the entry names.
        workspace: InstitutionWorkspaceId,
    },
}

impl std::fmt::Display for StateRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateRefusal::ForeignWorkspace { workspace } => write!(
                formatter,
                "the entry belongs to workspace {workspace:?}, not this store's"
            ),
        }
    }
}

impl std::error::Error for StateRefusal {}

/// One institution's current state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceState {
    workspace: InstitutionWorkspaceId,
    entries: BTreeMap<String, StateEntry>,
}

impl WorkspaceState {
    /// Open a store for the institution a boundary is scoped to.
    ///
    /// WHY the workspace comes from the boundary rather than from an argument:
    /// a store told its own identity is a store that can be told a different
    /// one from the boundary governing everything else, and both would then
    /// pass their own checks. Derived from the single source, it cannot.
    pub fn for_boundary<Outbox>(boundary: &InstitutionBoundary<Outbox>) -> Self {
        Self {
            workspace: boundary.workspace().clone(),
            entries: BTreeMap::new(),
        }
    }

    /// The institution this store serves.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Read the current value of one key.
    pub fn read(&self, key: &str) -> Option<&StateEntry> {
        self.entries.get(key)
    }

    /// Write an entry, replacing whatever the key held.
    ///
    /// Returns the replaced entry, if there was one. Ordinary state is meant to
    /// be replaced -- that is what separates it from evidence, which is
    /// corrected by appending -- and handing back the prior value means a
    /// caller who needs it does not have to have kept a copy against the
    /// possibility.
    ///
    /// # Errors
    ///
    /// Returns [`StateRefusal::ForeignWorkspace`] when the entry belongs to
    /// another institution.
    ///
    /// Time: O(log n). Space: O(1).
    pub fn write(&mut self, entry: StateEntry) -> Result<Option<StateEntry>, StateRefusal> {
        if entry.workspace != self.workspace {
            return Err(StateRefusal::ForeignWorkspace {
                workspace: entry.workspace,
            });
        }
        Ok(self.entries.insert(entry.key.clone(), entry))
    }

    /// How many keys the store holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstitutionId;

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    fn boundary() -> InstitutionBoundary<()> {
        InstitutionBoundary::new(InstitutionId::new(), InstitutionWorkspaceId::new(), ())
    }

    fn entry(workspace: &InstitutionWorkspaceId, key: &str, value: &[u8]) -> StateEntry {
        StateEntry {
            workspace: workspace.clone(),
            key: key.to_string(),
            value: Digest::blake3(value),
            written_at: now(),
            authority: PrincipalId::new(),
            authority_delegation: DelegationId::new(),
        }
    }

    #[test]
    fn a_store_takes_its_identity_from_the_boundary() {
        // Not from an argument. A store told its own identity can be told a
        // different one from the boundary governing everything else, and both
        // would then pass their own checks.
        let b = boundary();
        let store = WorkspaceState::for_boundary(&b);
        assert_eq!(store.workspace(), b.workspace());
        assert!(store.is_empty());
    }

    #[test]
    fn writing_replaces_and_hands_back_what_it_replaced() {
        // Ordinary state is meant to be replaced -- that is what separates it
        // from evidence, which is corrected by appending. Returning the prior
        // entry means a caller who needs it did not have to keep a copy against
        // the possibility.
        let b = boundary();
        let mut store = WorkspaceState::for_boundary(&b);
        let first = entry(b.workspace(), "commissioning.stage", b"reconnaissance");

        assert_eq!(store.write(first.clone()), Ok(None), "nothing was there");
        let second = entry(b.workspace(), "commissioning.stage", b"approval");
        assert_eq!(
            store.write(second.clone()),
            Ok(Some(first)),
            "the replaced entry comes back"
        );
        assert_eq!(store.read("commissioning.stage"), Some(&second));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn an_entry_from_another_institution_is_refused() {
        let b = boundary();
        let mut store = WorkspaceState::for_boundary(&b);
        let theirs = InstitutionWorkspaceId::new();
        let foreign = entry(&theirs, "commissioning.stage", b"reconnaissance");

        assert_eq!(
            store.write(foreign),
            Err(StateRefusal::ForeignWorkspace {
                workspace: theirs.clone()
            })
        );
        assert!(
            store.is_empty(),
            "a refused write must leave the store untouched"
        );
    }

    #[test]
    fn two_stores_on_one_boundary_agree_about_whose_institution_it_is() {
        // The property the collapse exists for. Both derive from one source, so
        // there is no arrangement in which they disagree.
        let b = boundary();
        let left = WorkspaceState::for_boundary(&b);
        let right = WorkspaceState::for_boundary(&b);
        assert_eq!(left.workspace(), right.workspace());
    }

    #[test]
    fn an_entry_names_its_value_rather_than_holding_it() {
        // `docs/16-DATA_GOVERNANCE.md` requires ordinary context to carry
        // references, not raw secret values. The field is a digest, so there is
        // nowhere for a secret to come to rest -- a stronger guarantee than a
        // rule saying not to, and this asserts the shape rather than the rule.
        let b = boundary();
        let held = entry(b.workspace(), "credential.database", b"hunter2");
        assert_eq!(held.value, Digest::blake3(b"hunter2"));
        assert_ne!(
            held.value.as_str(),
            "hunter2",
            "the entry must carry a reference to the value, never the value"
        );
    }

    #[test]
    fn every_refusal_variant_names_the_test_that_reaches_it() {
        // A refusal nothing can produce is a branch documenting a check rather
        // than performing one. Adding a variant stops the build here until its
        // test is named.
        let reached_by = |refusal: &StateRefusal| -> &'static str {
            match refusal {
                StateRefusal::ForeignWorkspace { .. } => {
                    "an_entry_from_another_institution_is_refused"
                }
            }
        };
        assert_eq!(
            reached_by(&StateRefusal::ForeignWorkspace {
                workspace: InstitutionWorkspaceId::new()
            }),
            "an_entry_from_another_institution_is_refused"
        );
    }
}
