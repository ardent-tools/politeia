//! Control runs, activation proofs, and what it takes to claim a clean result.
//!
//! A configured control can be bypassed, never invoked, run against the wrong
//! subject, or return a state that is not a failure and is not a pass either.
//! `docs/06-POLICY_COMPILER.md` names the consequence: promotion to an enforced
//! assurance state requires **activation evidence** -- a known violation
//! traversing the intended mediation path and producing the promised refusal,
//! with a known-good control admitted -- because unit tests prove local logic
//! and say nothing about whether the host invokes the control, preserves its
//! signal, or honours its result.
//!
//! The eight [`ControlResult`] states exist so that "nothing meaningful was
//! checked" has somewhere to go other than into a boolean's `false`, or worse
//! its `true`. `docs/02-CONSTITUTION.md` law 17 is the rule they serve: a clean
//! control result is meaningful only when evidence proves the control ran,
//! could observe its intended subject, and can fire on the real mediation path.
//!
//! WHY there is no `From<bool>`, no `Default`, and no fallible conversion into
//! `Clean`: every one of those is a place an adapter could map some other state
//! onto success, which is exactly what the state set exists to prevent.
//! [`clean_claim`] is the only route to a clean claim, and its match over the
//! eight states is exhaustive, so a state added later stops the build rather
//! than falling into whichever arm was written last.

use jiff::Timestamp;
use politeia_core::{Digest, EvidenceId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The exact result states a control run may report.
///
/// The set is closed and the names are the contract: `docs/03-ONTOLOGY.md`
/// fixes them, and `the_wire_tokens_are_the_ones_the_ontology_fixes` pins the
/// serialized form so a rename here cannot quietly redefine what a stored
/// result meant.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlResult {
    /// The control ran, observed its subject, and found nothing.
    Clean,
    /// The control ran and found what it looks for.
    Violation,
    /// The control did not run.
    NotRun,
    /// The control could not be reached.
    Unavailable,
    /// The control ran but could not decide.
    Unevaluable,
    /// The control ran over a population that should not have been empty.
    UnexpectedlyEmpty,
    /// The control does not apply to this subject.
    NotApplicable,
    /// The control's outcome is not established.
    Unresolved,
}

impl ControlResult {
    /// Every state, in declaration order.
    ///
    /// WHY built through an exhaustive match: a hand-kept list silently omits a
    /// state added later, and the omission is invisible -- the exhaustive-state
    /// test keeps passing while covering one state less, which is precisely the
    /// state nobody has decided how to treat.
    pub fn all() -> Vec<Self> {
        let complete = |result: Self| match result {
            Self::Clean
            | Self::Violation
            | Self::NotRun
            | Self::Unavailable
            | Self::Unevaluable
            | Self::UnexpectedlyEmpty
            | Self::NotApplicable
            | Self::Unresolved => (),
        };
        let states = vec![
            Self::Clean,
            Self::Violation,
            Self::NotRun,
            Self::Unavailable,
            Self::Unevaluable,
            Self::UnexpectedlyEmpty,
            Self::NotApplicable,
            Self::Unresolved,
        ];
        for state in &states {
            complete(*state);
        }
        states
    }
}

/// What a control run was able to observe, against what it was meant to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// The subjects the run was meant to observe.
    pub population: u64,
    /// The subjects it did observe.
    pub observed: u64,
}

impl Coverage {
    /// True when the run observed everything it was meant to.
    ///
    /// An empty population is not complete coverage. A control that observed
    /// nothing because there was nothing to observe has established nothing,
    /// and reporting that as full coverage is how an empty population becomes
    /// a clean bill of health.
    pub const fn is_complete(self) -> bool {
        self.population > 0 && self.observed >= self.population
    }
}

/// Real-path evidence that an exact control version can fire.
///
/// Both halves are required and neither substitutes for the other: a control
/// that refuses everything refuses the planted violation too, and a control
/// that is never invoked admits the known-good subject just as silently as a
/// working one does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationProof {
    /// This proof's identity as an admitted record.
    pub id: EvidenceId,
    /// The control the proof is about.
    pub control: String,
    /// The exact control version proved.
    pub control_version: String,
    /// Digest of the exact configuration proved.
    pub configuration_digest: Digest,
    /// The mediation path the control was exercised on.
    pub mediation_path: String,
    /// Digest of the known violation planted on that path.
    pub planted_violation: Digest,
    /// What the control reported for it. Must be [`ControlResult::Violation`].
    pub planted_violation_result: ControlResult,
    /// Digest of the known-good subject.
    pub known_good: Digest,
    /// What the control reported for it. Must be [`ControlResult::Clean`].
    pub known_good_result: ControlResult,
    /// The retained evidence of the exercise.
    pub retained_evidence: EvidenceId,
    /// When the proof was produced.
    pub proved_at: Timestamp,
}

/// One control invocation, bound to what it ran against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlRun {
    /// This run's identity as an admitted record.
    pub id: EvidenceId,
    /// The control invoked.
    pub control: String,
    /// The exact control version invoked.
    pub control_version: String,
    /// Digest of the exact configuration invoked.
    pub configuration_digest: Digest,
    /// Digest of the exact admitted input.
    pub input_digest: Digest,
    /// Digest of the exact subject judged.
    pub subject: Digest,
    /// Digest of the authorization the run was performed under.
    pub authorization: Digest,
    /// The mediation path the run sat on.
    pub mediation_path: String,
    /// When the run began.
    pub started_at: Timestamp,
    /// When the run ended.
    pub finished_at: Timestamp,
    /// The typed result.
    pub result: ControlResult,
    /// What the run observed.
    pub coverage: Coverage,
    /// The principal that performed the run.
    pub verifier: PrincipalId,
}

/// Why a set of runs does not support a clean claim.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimRefusal {
    /// No run judged this subject.
    NoRun,
    /// The same control ran more than once over the same input and subject.
    ///
    /// WHY this refuses rather than choosing: with two results in hand the
    /// tempting move is to take the clean one, and that is precisely the move
    /// that turns a flaky or bypassed control into a passing claim.
    DuplicateInvocation {
        /// The control invoked twice.
        control: String,
    },
    /// The run reported something other than clean.
    ResultNotClean(ControlResult),
    /// The run did not observe everything it was meant to.
    PartialCoverage {
        /// What it observed.
        observed: u64,
        /// What it was meant to observe.
        population: u64,
    },
    /// The run observed nothing because there was nothing to observe.
    EmptyPopulation,
    /// The run ended before it began.
    InvertedInterval,
    /// The activation proof is about a different control.
    ActivationControlMismatch,
    /// The activation proof is about a different control version.
    ActivationVersionMismatch,
    /// The activation proof is about a different configuration.
    ActivationConfigurationMismatch,
    /// The activation proof exercised a different mediation path.
    ActivationPathMismatch,
    /// The planted violation did not produce a refusal.
    ActivationDidNotRefuse(ControlResult),
    /// The known-good subject was not admitted.
    ActivationRejectedKnownGood(ControlResult),
}

impl std::fmt::Display for ClaimRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimRefusal::NoRun => formatter.write_str("no control run judged this subject"),
            ClaimRefusal::DuplicateInvocation { control } => write!(
                formatter,
                "control {control} ran more than once over the same input and subject"
            ),
            ClaimRefusal::ResultNotClean(result) => {
                write!(formatter, "the control reported {result:?}, not clean")
            }
            ClaimRefusal::PartialCoverage {
                observed,
                population,
            } => write!(
                formatter,
                "the control observed {observed} of {population} subjects"
            ),
            ClaimRefusal::EmptyPopulation => {
                formatter.write_str("the control observed an empty population")
            }
            ClaimRefusal::InvertedInterval => {
                formatter.write_str("the control run ended before it began")
            }
            ClaimRefusal::ActivationControlMismatch => {
                formatter.write_str("the activation proof is about a different control")
            }
            ClaimRefusal::ActivationVersionMismatch => {
                formatter.write_str("the activation proof is about a different control version")
            }
            ClaimRefusal::ActivationConfigurationMismatch => {
                formatter.write_str("the activation proof is about a different configuration")
            }
            ClaimRefusal::ActivationPathMismatch => {
                formatter.write_str("the activation proof exercised a different mediation path")
            }
            ClaimRefusal::ActivationDidNotRefuse(result) => write!(
                formatter,
                "the planted violation produced {result:?} rather than a refusal"
            ),
            ClaimRefusal::ActivationRejectedKnownGood(result) => write!(
                formatter,
                "the known-good subject produced {result:?} rather than clean"
            ),
        }
    }
}

impl std::error::Error for ClaimRefusal {}

/// The one route to a clean assurance claim.
///
/// Every check here is a way the claim fails; there is no other way for it to
/// succeed. That is deliberate and is the module's whole shape: an adapter
/// cannot reach a clean claim by any path except a run whose result is
/// literally [`ControlResult::Clean`], over complete coverage, with an
/// activation proof binding the same control version, configuration and
/// mediation path, and showing both that the planted violation was refused and
/// that the known-good subject was admitted.
///
/// WHY the claim names one control rather than judging a subject in general:
/// several controls may judge one subject, and a function that took only the
/// subject would have to choose among their runs. Any choice is arbitrary and
/// order-dependent, and the tempting one -- the first clean result -- is the
/// bug. An assurance case is built claim by claim, one control at a time, so
/// the signature says so.
///
/// # Errors
///
/// Returns the first [`ClaimRefusal`] that applies. Checks run from the cheapest
/// and most specific outward, so the reported reason is the one nearest to what
/// the caller controls.
///
/// Time: O(n) for n runs. Space: O(1).
pub fn clean_claim<'run>(
    runs: &'run [ControlRun],
    control: &str,
    subject: &Digest,
    activation: &ActivationProof,
) -> Result<&'run ControlRun, ClaimRefusal> {
    let mut judged = runs
        .iter()
        .filter(|run| run.control == control && &run.subject == subject);

    let Some(run) = judged.next() else {
        return Err(ClaimRefusal::NoRun);
    };
    // WHY any second run refuses, whatever it says: two invocations of one
    // control over one subject leave nothing saying which is authoritative.
    // Agreement does not help -- it is also what a control returning a
    // constant produces -- and disagreement is where taking the clean one
    // turns a flaky or partly-bypassed control into a passing claim.
    if judged.next().is_some() {
        return Err(ClaimRefusal::DuplicateInvocation {
            control: control.to_string(),
        });
    }

    // The exhaustive match is the point. A state added later has no arm and the
    // build stops, rather than the new state falling through to whichever
    // branch a boolean projection would have put it in.
    match run.result {
        ControlResult::Clean => {}
        other @ (ControlResult::Violation
        | ControlResult::NotRun
        | ControlResult::Unavailable
        | ControlResult::Unevaluable
        | ControlResult::UnexpectedlyEmpty
        | ControlResult::NotApplicable
        | ControlResult::Unresolved) => return Err(ClaimRefusal::ResultNotClean(other)),
    }

    if run.finished_at < run.started_at {
        return Err(ClaimRefusal::InvertedInterval);
    }
    if run.coverage.population == 0 {
        return Err(ClaimRefusal::EmptyPopulation);
    }
    if !run.coverage.is_complete() {
        return Err(ClaimRefusal::PartialCoverage {
            observed: run.coverage.observed,
            population: run.coverage.population,
        });
    }

    if activation.control != run.control {
        return Err(ClaimRefusal::ActivationControlMismatch);
    }
    if activation.control_version != run.control_version {
        return Err(ClaimRefusal::ActivationVersionMismatch);
    }
    if activation.configuration_digest != run.configuration_digest {
        return Err(ClaimRefusal::ActivationConfigurationMismatch);
    }
    if activation.mediation_path != run.mediation_path {
        return Err(ClaimRefusal::ActivationPathMismatch);
    }
    if activation.planted_violation_result != ControlResult::Violation {
        return Err(ClaimRefusal::ActivationDidNotRefuse(
            activation.planted_violation_result,
        ));
    }
    if activation.known_good_result != ControlResult::Clean {
        return Err(ClaimRefusal::ActivationRejectedKnownGood(
            activation.known_good_result,
        ));
    }

    Ok(run)
}
