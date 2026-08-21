//! Bounded reconnaissance: what a commissioner may look at, and for how long.
//!
//! `docs/03-ONTOLOGY.md` describes a commissioner as a temporarily delegated
//! principal whose authority is *explicit, scoped, expiring/revocable, and
//! never self-issued*. Each of those four words is a way the authority can be
//! wrong, and this module is the four checks.
//!
//! WHY read-only is checked rather than described: an adapter is called
//! "read-only" in prose everywhere in the corpus, and prose does not stop one
//! from writing. A reconnaissance delegation carrying `WriteExternalSystem` is
//! not a read-only pass however it is labelled, so the scope refuses it --
//! [`Effect::mutates`] is what decides, exhaustively, so a new effect variant
//! has to be classified rather than defaulting into the permitted set.
//!
//! Everything here refuses; nothing here reaches a source. Producing the
//! observations is an adapter's job, and admitting them is this one's, because
//! the two questions have different answers and want different reviewers.

use std::collections::BTreeSet;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::knowledge::Observation;
use crate::{
    AdapterId, Delegation, DelegationId, Effect, InstitutionId, InstitutionWorkspaceId, PrincipalId,
};

/// The semantic action a delegation must carry to reconnoitre.
pub const RECONNOITRE_ACTION: &str = "reconnaissance.observe";

/// What one reconnaissance pass is permitted to look at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnaissanceScope {
    /// The institution being commissioned.
    pub institution: InstitutionId,
    /// The workspace the observations belong to.
    pub workspace: InstitutionWorkspaceId,
    /// The commissioner performing the pass.
    pub commissioner: PrincipalId,
    /// The exact delegation carrying its authority.
    pub delegation: DelegationId,
    /// The sources it may reach, as the institution names them.
    pub sources: BTreeSet<String>,
    /// The exact adapters it may reach them through.
    pub adapters: BTreeSet<AdapterId>,
    /// When the pass stops being permitted.
    pub expires_at: Timestamp,
}

/// Why an observation is not admissible under a scope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconnaissanceRefusal {
    /// The scope has expired.
    ScopeExpired,
    /// The delegation carrying the authority has expired.
    ///
    /// Distinct from the scope expiring: a scope can outlive the delegation it
    /// was cut from, and a check that compares only one of them admits work
    /// under authority that is already gone.
    AuthorityExpired,
    /// The delegation names a different principal.
    AuthorityMismatch,
    /// The delegation was issued by the principal that holds it.
    ///
    /// `docs/03-ONTOLOGY.md`: a commissioner's authority is *never
    /// self-issued*. A self-issued delegation passes every other check here --
    /// it is well-formed, scoped, and unexpired -- and answers the question
    /// "who said you could" with "I did".
    SelfIssuedAuthority,
    /// The delegation does not carry the reconnaissance action.
    ActionNotDelegated,
    /// The delegation carries an effect that changes something.
    NotReadOnly {
        /// The effects that mutate.
        effects: BTreeSet<Effect>,
    },
    /// The observation belongs to another workspace.
    ///
    /// The cross-institution case. It is checked before the source and adapter
    /// because those are questions about *this* institution's scope, and an
    /// observation from another one is not in scope by any answer to them.
    ForeignWorkspace {
        /// The workspace the observation names.
        workspace: InstitutionWorkspaceId,
    },
    /// The observation names a source outside the scope.
    SourceOutOfScope {
        /// The source observed.
        source: String,
    },
    /// The observation was taken through an adapter outside the scope.
    AdapterOutOfScope {
        /// The adapter used.
        adapter: AdapterId,
    },
    /// The observation was taken at or after the scope expired.
    ///
    /// Checked against the observation's own moment rather than the clock:
    /// whether the pass was authorised when it looked is a fact about then,
    /// and admitting late work because it is being reviewed early is the whole
    /// of what an expiry prevents.
    ObservedAfterExpiry,
}

impl std::fmt::Display for ReconnaissanceRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconnaissanceRefusal::ScopeExpired => {
                formatter.write_str("the reconnaissance scope has expired")
            }
            ReconnaissanceRefusal::AuthorityExpired => {
                formatter.write_str("the delegation carrying the scope has expired")
            }
            ReconnaissanceRefusal::AuthorityMismatch => {
                formatter.write_str("the delegation was issued to another principal")
            }
            ReconnaissanceRefusal::SelfIssuedAuthority => {
                formatter.write_str("the commissioner issued its own authority")
            }
            ReconnaissanceRefusal::ActionNotDelegated => write!(
                formatter,
                "the delegation does not carry {RECONNOITRE_ACTION}"
            ),
            ReconnaissanceRefusal::NotReadOnly { effects } => write!(
                formatter,
                "a reconnaissance delegation may not carry mutating effects: {effects:?}"
            ),
            ReconnaissanceRefusal::ForeignWorkspace { workspace } => write!(
                formatter,
                "the observation belongs to workspace {workspace:?}, not this scope's"
            ),
            ReconnaissanceRefusal::SourceOutOfScope { source } => {
                write!(formatter, "source {source} is outside the scope")
            }
            ReconnaissanceRefusal::AdapterOutOfScope { adapter } => {
                write!(formatter, "adapter {adapter:?} is outside the scope")
            }
            ReconnaissanceRefusal::ObservedAfterExpiry => {
                formatter.write_str("the observation was taken after the scope expired")
            }
        }
    }
}

impl std::error::Error for ReconnaissanceRefusal {}

impl ReconnaissanceScope {
    /// Check the authority behind this scope, independently of any observation.
    ///
    /// Separated so that a pass can be refused before it reaches a source
    /// rather than after: an expired or self-issued authority is a reason not
    /// to look, and discovering it while admitting results means the looking
    /// already happened.
    ///
    /// # Errors
    ///
    /// Returns [`ReconnaissanceRefusal`] when the scope or its delegation has
    /// expired, when the delegation belongs to another principal, when the
    /// commissioner issued it to itself, when it lacks the reconnaissance
    /// action, or when it carries an effect that mutates.
    ///
    /// Time: O(e) for e delegated effects. Space: O(e).
    pub fn admit_authority(
        &self,
        delegation: &Delegation,
        now: Timestamp,
    ) -> Result<(), ReconnaissanceRefusal> {
        if now >= self.expires_at {
            return Err(ReconnaissanceRefusal::ScopeExpired);
        }
        if delegation.id != self.delegation || delegation.subject != self.commissioner {
            return Err(ReconnaissanceRefusal::AuthorityMismatch);
        }
        if delegation.issuer == self.commissioner {
            return Err(ReconnaissanceRefusal::SelfIssuedAuthority);
        }
        if delegation.is_expired(now) {
            return Err(ReconnaissanceRefusal::AuthorityExpired);
        }
        if !delegation.actions.contains(RECONNOITRE_ACTION) {
            return Err(ReconnaissanceRefusal::ActionNotDelegated);
        }
        let mutating: BTreeSet<Effect> = delegation
            .effects
            .iter()
            .filter(|effect| effect.mutates())
            .cloned()
            .collect();
        if !mutating.is_empty() {
            return Err(ReconnaissanceRefusal::NotReadOnly { effects: mutating });
        }
        Ok(())
    }

    /// Admit one observation produced under this scope.
    ///
    /// # Errors
    ///
    /// Returns [`ReconnaissanceRefusal`] for everything
    /// [`Self::admit_authority`] refuses, plus an observation from a source or
    /// through an adapter the scope does not name, or taken at or after the
    /// scope expired.
    ///
    /// Time: O(log n) in the scoped source and adapter counts, plus the
    /// authority check. Space: O(1).
    pub fn admit(
        &self,
        delegation: &Delegation,
        observation: &Observation,
        now: Timestamp,
    ) -> Result<(), ReconnaissanceRefusal> {
        self.admit_authority(delegation, now)?;

        if observation.workspace != self.workspace {
            return Err(ReconnaissanceRefusal::ForeignWorkspace {
                workspace: observation.workspace.clone(),
            });
        }
        if observation.observed_at >= self.expires_at {
            return Err(ReconnaissanceRefusal::ObservedAfterExpiry);
        }
        if !self.sources.contains(&observation.source) {
            return Err(ReconnaissanceRefusal::SourceOutOfScope {
                source: observation.source.clone(),
            });
        }
        if !self.adapters.contains(&observation.adapter) {
            return Err(ReconnaissanceRefusal::AdapterOutOfScope {
                adapter: observation.adapter.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::*;
    use crate::{DataClass, Digest, EvidenceId, ObservationId, ResourceBudget};

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    fn expiry() -> Timestamp {
        now() + SignedDuration::from_hours(4)
    }

    struct Fixture {
        scope: ReconnaissanceScope,
        delegation: Delegation,
        observation: Observation,
    }

    fn fixture() -> Fixture {
        let commissioner = PrincipalId::new();
        let delegation_id = DelegationId::new();
        let adapter = AdapterId::new();
        let delegation = Delegation {
            id: delegation_id.clone(),
            issuer: PrincipalId::new(),
            subject: commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([RECONNOITRE_ACTION.to_string()]),
            resources: BTreeSet::from(["crm:contacts".to_string()]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["commissioning".to_string()]),
            expires_at: expiry(),
            budget: ResourceBudget {
                wall_ms: Some(1),
                cpu_ms: Some(1),
                memory_bytes: Some(1),
                io_bytes: Some(1),
                network_bytes: Some(1),
                external_cost_microunits: Some(1),
            },
        };
        let workspace = InstitutionWorkspaceId::new();
        Fixture {
            scope: ReconnaissanceScope {
                institution: InstitutionId::new(),
                workspace: workspace.clone(),
                commissioner,
                delegation: delegation_id,
                sources: BTreeSet::from(["crm".to_string()]),
                adapters: BTreeSet::from([adapter.clone()]),
                expires_at: expiry(),
            },
            delegation,
            observation: Observation {
                id: ObservationId::new(),
                workspace: workspace.clone(),
                source: "crm".to_string(),
                adapter,
                subject: Digest::blake3(b"the institution's billing contact"),
                statement: Digest::blake3(b"finance handles billing"),
                observed_at: now(),
                evidence: EvidenceId::new(),
            },
        }
    }

    #[test]
    fn an_in_scope_observation_is_admitted() {
        let f = fixture();
        assert_eq!(f.scope.admit(&f.delegation, &f.observation, now()), Ok(()));
    }

    #[test]
    fn a_self_issued_authority_is_refused() {
        // It passes every other check here -- well-formed, scoped, unexpired,
        // carrying the action and no mutating effect -- and answers "who said
        // you could" with "I did".
        let mut f = fixture();
        f.delegation.issuer = f.scope.commissioner.clone();
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::SelfIssuedAuthority)
        );
    }

    #[test]
    fn a_delegation_carrying_a_mutating_effect_is_not_read_only() {
        // "Read-only adapter" is prose everywhere in the corpus, and prose does
        // not stop anyone writing.
        let mut f = fixture();
        f.delegation.effects.insert(Effect::WriteExternalSystem);
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::NotReadOnly {
                effects: BTreeSet::from([Effect::WriteExternalSystem]),
            })
        );
    }

    #[test]
    fn every_read_effect_is_permitted_and_every_other_is_not() {
        // The classification itself, over the whole enum rather than the two
        // variants the fixtures happen to use. A new effect added and never
        // classified would stop the build in `mutates`; this checks the
        // classification it was given actually reaches this refusal.
        for effect in [
            Effect::ReadFilesystem,
            Effect::ReadSecret,
            Effect::ReadExternalSystem,
            Effect::WriteFilesystem,
            Effect::SpawnProcess,
            Effect::NetworkEgress,
            Effect::WriteSecret,
            Effect::WriteExternalSystem,
            Effect::CreateArtifact,
            Effect::ChangeAuthorization,
        ] {
            let mut f = fixture();
            f.delegation.effects = BTreeSet::from([effect.clone()]);
            let admitted = f.scope.admit(&f.delegation, &f.observation, now()).is_ok();
            assert_eq!(
                admitted,
                !effect.mutates(),
                "{effect:?} was admitted={admitted} against mutates={}",
                effect.mutates()
            );
        }
    }

    #[test]
    fn an_expired_scope_refuses_before_anything_is_read() {
        let f = fixture();
        assert_eq!(
            f.scope.admit_authority(&f.delegation, expiry()),
            Err(ReconnaissanceRefusal::ScopeExpired),
            "expiry is inclusive: at the moment it expires it is expired"
        );
    }

    #[test]
    fn a_delegation_that_expires_before_the_scope_is_refused() {
        // A scope can outlive the delegation it was cut from, and a check that
        // compares only one of them admits work under authority already gone.
        let mut f = fixture();
        f.delegation.expires_at = now() + SignedDuration::from_hours(1);
        let after = now() + SignedDuration::from_hours(2);
        assert_eq!(
            f.scope.admit_authority(&f.delegation, after),
            Err(ReconnaissanceRefusal::AuthorityExpired),
            "the scope is still live and the authority is not"
        );
    }

    #[test]
    fn a_delegation_belonging_to_another_principal_is_refused() {
        let mut f = fixture();
        f.delegation.subject = PrincipalId::new();
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::AuthorityMismatch)
        );
    }

    #[test]
    fn a_different_delegation_than_the_scope_names_is_refused() {
        let mut f = fixture();
        f.delegation.id = DelegationId::new();
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::AuthorityMismatch)
        );
    }

    #[test]
    fn a_delegation_without_the_action_is_refused() {
        let mut f = fixture();
        f.delegation.actions = BTreeSet::from(["something.else".to_string()]);
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::ActionNotDelegated)
        );
    }

    #[test]
    fn an_observation_from_another_workspace_is_refused() {
        // The cross-institution case. Every other field is in scope: the source
        // is named, the adapter is named, the authority is live. The material
        // simply belongs to somebody else, and `docs/16-DATA_GOVERNANCE.md`
        // requires an explicit authorized export rather than an inference.
        let mut f = fixture();
        f.observation.workspace = InstitutionWorkspaceId::new();
        assert!(matches!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::ForeignWorkspace { .. })
        ));
    }

    #[test]
    fn a_source_the_scope_does_not_name_is_refused() {
        let mut f = fixture();
        f.observation.source = "payroll".to_string();
        assert_eq!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::SourceOutOfScope {
                source: "payroll".to_string(),
            })
        );
    }

    #[test]
    fn an_adapter_the_scope_does_not_name_is_refused() {
        // Distinct from the source: the same source reached through an
        // unreviewed adapter is an unreviewed path to reviewed data.
        let mut f = fixture();
        f.observation.adapter = AdapterId::new();
        assert!(matches!(
            f.scope.admit(&f.delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::AdapterOutOfScope { .. })
        ));
    }

    #[test]
    fn an_observation_taken_after_expiry_is_refused_even_when_reviewed_in_time() {
        // Whether the pass was authorised when it looked is a fact about then.
        // Admitting late work because it is being reviewed early is the whole
        // of what an expiry prevents.
        let mut f = fixture();
        f.observation.observed_at = expiry() + SignedDuration::from_mins(1);
        f.scope.expires_at = expiry() + SignedDuration::from_hours(2);
        f.delegation.expires_at = f.scope.expires_at;

        let scope = ReconnaissanceScope {
            expires_at: expiry(),
            ..f.scope.clone()
        };
        let delegation = Delegation {
            expires_at: expiry() + SignedDuration::from_hours(2),
            ..f.delegation.clone()
        };
        assert_eq!(
            scope.admit(&delegation, &f.observation, now()),
            Err(ReconnaissanceRefusal::ObservedAfterExpiry)
        );
    }
}
