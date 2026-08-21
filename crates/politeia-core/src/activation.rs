//! Activating a runtime generation, and keeping what may not be activated.
//!
//! `docs/11-FAILURE_SEMANTICS.md` sets both halves:
//!
//! > Generation derivation and activation are atomic. Failure retains the last
//! > known good generation.
//!
//! > The system quarantines output on undeclared nondeterminism,
//! > institution/workspace mismatch, or cross-institution input; it does not
//! > activate that output.
//!
//! WHY there is no `rollback`: atomicity already is the rollback. A refused
//! activation changes nothing, so there is no intermediate state to return
//! from — and a `rollback` method would imply one exists, which is the reading
//! that leads to a system briefly running a generation it later un-runs.
//!
//! WHY a refusal hands the candidate back rather than dropping it: *quarantine*
//! and *discard* are different outcomes, and the document asks for the first.
//! A caller that receives [`QuarantinedGeneration`] can store it, inspect it, or
//! re-derive against it; a caller handed a bare error has lost the output it was
//! told to keep.

use std::collections::BTreeSet;

use crate::InstitutionWorkspaceId;
use crate::generation::{ReproducibilityContract, RuntimeGeneration};
use crate::institution::{InstitutionBoundary, WorkspaceScoped};

impl WorkspaceScoped for RuntimeGeneration {
    fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.inputs().workspace
    }
}

/// Why a candidate generation may not be activated.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ineligibility {
    /// The candidate was derived for another institution.
    ForeignInstitution {
        /// The workspace the candidate names.
        workspace: InstitutionWorkspaceId,
    },
    /// Derivation varied in fields the reproducibility contract does not cover.
    ///
    /// Under [`ReproducibilityContract::Deterministic`] that is any variance at
    /// all. Under `DeclaredNondeterminism` it is the variance outside the
    /// declared set — the declaration is what makes nondeterminism admissible,
    /// so anything it does not name is undeclared by definition.
    UndeclaredNondeterminism {
        /// The fields that varied without cover.
        fields: BTreeSet<String>,
    },
}

impl std::fmt::Display for Ineligibility {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ineligibility::ForeignInstitution { workspace } => write!(
                formatter,
                "the candidate was derived for workspace {workspace:?}"
            ),
            Ineligibility::UndeclaredNondeterminism { fields } => write!(
                formatter,
                "derivation varied in {fields:?}, which the reproducibility contract does not declare"
            ),
        }
    }
}

impl std::error::Error for Ineligibility {}

/// A candidate that was not activated, kept rather than discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedGeneration {
    /// Why it was refused.
    pub reason: Ineligibility,
    /// The candidate exactly as offered.
    ///
    /// WHY boxed: a refusal carries a whole generation, and an unboxed error
    /// that large makes every successful activation pay its size. The candidate
    /// still travels with the reason -- quarantine and discard remain different
    /// outcomes -- it simply travels behind one indirection.
    pub candidate: Box<RuntimeGeneration>,
}

impl std::fmt::Display for QuarantinedGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "quarantined generation: {}", self.reason)
    }
}

impl std::error::Error for QuarantinedGeneration {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// The generation an institution is currently running.
///
/// There is always exactly one. The type has no empty state because a system
/// between generations is the condition atomicity exists to prevent, and a
/// representable empty state is one a caller will eventually be handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGeneration {
    active: RuntimeGeneration,
}

impl ActiveGeneration {
    /// Begin with a known-good generation.
    pub fn new(active: RuntimeGeneration) -> Self {
        Self { active }
    }

    /// The generation currently running.
    pub fn current(&self) -> &RuntimeGeneration {
        &self.active
    }

    /// Activate a candidate, or quarantine it and keep running what runs.
    ///
    /// `observed_variance` is the set of canonical field paths that differed
    /// between derivations of this candidate. Detecting variance takes two
    /// derivations and belongs to the caller; judging it against the
    /// reproducibility contract belongs here.
    ///
    /// # Errors
    ///
    /// Returns [`QuarantinedGeneration`] — carrying the candidate — when the
    /// candidate belongs to another institution, or when derivation varied in
    /// fields its reproducibility contract does not declare. In either case the
    /// generation already running is untouched.
    ///
    /// Time: O(v log d) for v observed fields against d declared. Space: O(v).
    pub fn activate<Outbox>(
        &mut self,
        boundary: &InstitutionBoundary<Outbox>,
        candidate: RuntimeGeneration,
        observed_variance: &BTreeSet<String>,
    ) -> Result<RuntimeGeneration, QuarantinedGeneration> {
        // Every check runs before anything is written, which is what makes this
        // atomic. There is no partial state to unwind because none is ever
        // created.
        if !boundary.owns(&candidate) {
            return Err(QuarantinedGeneration {
                reason: Ineligibility::ForeignInstitution {
                    workspace: candidate.workspace().clone(),
                },
                candidate: Box::new(candidate),
            });
        }

        let undeclared: BTreeSet<String> = match &candidate.inputs().approved.reproducibility {
            ReproducibilityContract::Deterministic => observed_variance.clone(),
            ReproducibilityContract::DeclaredNondeterminism { fields, .. } => {
                observed_variance.difference(fields).cloned().collect()
            }
        };
        if !undeclared.is_empty() {
            return Err(QuarantinedGeneration {
                reason: Ineligibility::UndeclaredNondeterminism { fields: undeclared },
                candidate: Box::new(candidate),
            });
        }

        Ok(std::mem::replace(&mut self.active, candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::generation::{ReproducibilityContract, RuntimeGenerationInputs};
    use crate::institution::InstitutionBoundary;
    use crate::test_support::{Fixture, fixture, fixture_with};

    // WHY every helper takes the fixture rather than calling `fixture()`: each
    // call mints fresh identities, so inputs from one call and a workspace from
    // another do not describe the same institution -- and `derive` rejects the
    // pair on provenance rather than producing a subtly wrong generation. One
    // fixture, one institution.
    #[expect(
        clippy::expect_used,
        reason = "a fixture whose generation cannot derive is a broken test, not a finding"
    )]
    fn generation(f: &Fixture, inputs: RuntimeGenerationInputs) -> RuntimeGeneration {
        RuntimeGeneration::derive(inputs, &f.workspace, &f.commissioning)
            .expect("the fixture inputs derive a generation")
    }

    fn generation_of(f: &Fixture) -> RuntimeGeneration {
        generation(f, f.inputs.clone())
    }

    fn boundary_for(generation: &RuntimeGeneration) -> InstitutionBoundary<()> {
        InstitutionBoundary::new(
            generation.inputs().institution.clone(),
            generation.inputs().workspace.clone(),
            (),
        )
    }

    fn nothing() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn a_deterministic_candidate_with_no_variance_activates() {
        let f = fixture();
        let running = generation_of(&f);
        let b = boundary_for(&running);
        let mut active = ActiveGeneration::new(running.clone());

        let candidate = generation_of(&f);
        let replaced = active.activate(&b, candidate.clone(), &nothing());
        assert_eq!(replaced, Ok(running));
        assert_eq!(active.current(), &candidate);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_candidate_from_another_institution_is_quarantined_and_nothing_changes() {
        let f = fixture();
        let running = generation_of(&f);
        let b = boundary_for(&running);
        let mut active = ActiveGeneration::new(running.clone());

        // A second fixture is a second institution: fresh identities all the
        // way down, and internally consistent, which is what makes it a fair
        // test of the boundary rather than of provenance validation.
        let theirs = fixture();
        let foreign = generation_of(&theirs);

        let refused = active
            .activate(&b, foreign.clone(), &nothing())
            .expect_err("a foreign candidate must not activate");
        assert!(matches!(
            refused.reason,
            Ineligibility::ForeignInstitution { .. }
        ));
        assert_eq!(
            *refused.candidate, foreign,
            "the candidate is quarantined, not discarded"
        );
        assert_eq!(
            active.current(),
            &running,
            "failure retains the last known good generation"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn any_variance_at_all_is_undeclared_under_a_deterministic_contract() {
        // `Deterministic` means exact inputs reproduce identical bytes, so a
        // field that varied is by definition uncovered -- there is no
        // declaration for it to fall under.
        let f = fixture();
        let running = generation_of(&f);
        let b = boundary_for(&running);
        let mut active = ActiveGeneration::new(running.clone());

        let varied = BTreeSet::from(["build.timestamp".to_string()]);
        let refused = active
            .activate(&b, generation_of(&f), &varied)
            .expect_err("undeclared variance must not activate");
        assert_eq!(
            refused.reason,
            Ineligibility::UndeclaredNondeterminism { fields: varied }
        );
        assert_eq!(active.current(), &running);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn declared_fields_may_vary_and_others_may_not() {
        let f = fixture_with(ReproducibilityContract::DeclaredNondeterminism {
            fields: BTreeSet::from(["build.timestamp".to_string()]),
            contract_digest: Digest::blake3(b"the nondeterminism contract"),
        });
        let declared_inputs = f.inputs.clone();
        let running = generation(&f, declared_inputs.clone());
        let b = boundary_for(&running);
        let mut active = ActiveGeneration::new(running.clone());

        let covered = BTreeSet::from(["build.timestamp".to_string()]);
        assert!(
            active
                .activate(&b, generation(&f, declared_inputs.clone()), &covered)
                .is_ok(),
            "a declared field may vary"
        );

        let mixed = BTreeSet::from(["build.timestamp".to_string(), "adapter.digest".to_string()]);
        let refused = active
            .activate(&b, generation(&f, declared_inputs), &mixed)
            .expect_err("an undeclared field alongside a declared one must refuse");
        assert_eq!(
            refused.reason,
            Ineligibility::UndeclaredNondeterminism {
                fields: BTreeSet::from(["adapter.digest".to_string()]),
            },
            "the refusal names only what was not declared"
        );
    }

    #[test]
    fn there_is_no_state_in_which_nothing_is_active() {
        // Atomicity, as a property of the type rather than of the method.
        // `ActiveGeneration` has no empty variant, so a system between
        // generations is unrepresentable -- which is why there is no `rollback`
        // to return from one.
        let f = fixture();
        let running = generation_of(&f);
        let b = boundary_for(&running);
        let mut active = ActiveGeneration::new(running.clone());

        let theirs = fixture();
        let _ = active.activate(&b, generation_of(&theirs), &nothing());
        assert_eq!(active.current(), &running);

        let _ = active.activate(
            &b,
            generation_of(&f),
            &BTreeSet::from(["anything".to_string()]),
        );
        assert_eq!(
            active.current(),
            &running,
            "two refusals in a row still leave exactly one generation running"
        );
    }

    #[test]
    fn every_ineligibility_names_the_test_that_reaches_it() {
        let reached_by = |reason: &Ineligibility| -> &'static str {
            match reason {
                Ineligibility::ForeignInstitution { .. } => {
                    "a_candidate_from_another_institution_is_quarantined_and_nothing_changes"
                }
                Ineligibility::UndeclaredNondeterminism { .. } => {
                    "any_variance_at_all_is_undeclared_under_a_deterministic_contract"
                }
            }
        };
        assert_eq!(
            reached_by(&Ineligibility::UndeclaredNondeterminism { fields: nothing() }),
            "any_variance_at_all_is_undeclared_under_a_deterministic_contract"
        );
    }
}
