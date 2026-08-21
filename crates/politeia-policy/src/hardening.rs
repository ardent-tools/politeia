//! The progressive-hardening ladder: the one authority for how a binding gains
//! blocking power.
//!
//! `README.md` states the property as prose -- observe, model, approve, shadow,
//! calibrate, enforce, structural -- and `spec/policy-lifecycle.yaml` publishes
//! it as a table. Both are projections of what is declared here. The table is
//! derived from these types by `cargo run -p xtask -- derive`; the prose is
//! written by hand and is the one restatement, kept because a README that
//! points at a YAML file communicates nothing.
//!
//! The table is *necessary, not sufficient*. No other transition is
//! structurally valid; policy may impose additional owner approval, evidence,
//! or separation-of-duty requirements on the transitions that are. It may not
//! invent a shortcut around one. Promotion to `Enforced` is the standing
//! example: `docs/06-POLICY_COMPILER.md` requires activation evidence -- a
//! known violation traversing the real mediation path and producing the
//! promised refusal -- which no table of edges can express.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::Consequence;

/// A rung of the progressive-hardening ladder.
///
/// The ladder describes a *binding's* authority, not a detector's quality.
/// `Calibrated` here means the binding has been calibrated in shadow; a
/// detector's own calibration is [`crate::DetectorSpec`]'s
/// `adversarially_calibrated`, which is a different fact about a different
/// subject and deliberately no longer shares the word.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HardeningState {
    /// Nothing has been observed about the property.
    Unknown,
    /// The property has been observed but not modelled.
    Observed,
    /// A clause and binding have been proposed.
    Proposed,
    /// The proposal has been approved.
    Approved,
    /// Evaluated on the real path, recording only.
    Shadow,
    /// Calibrated in shadow against real traffic.
    Calibrated,
    /// Surfaced as advice.
    Advisory,
    /// Blocking.
    Enforced,
    /// Made impossible by structure rather than by a check.
    Structural,
    /// Withdrawn from service.
    Retired,
}

impl HardeningState {
    /// Every rung, in ladder order.
    ///
    /// WHY built through an exhaustive match: a hand-kept list silently omits a
    /// variant added later, and the omission is invisible -- the projection
    /// below and every test above keep passing while covering one rung less.
    /// Matching exhaustively means a new variant stops the build until it is
    /// listed here and given its successors.
    pub fn all() -> Vec<Self> {
        let complete = |state: Self| match state {
            Self::Unknown
            | Self::Observed
            | Self::Proposed
            | Self::Approved
            | Self::Shadow
            | Self::Calibrated
            | Self::Advisory
            | Self::Enforced
            | Self::Structural
            | Self::Retired => (),
        };

        let states = vec![
            Self::Unknown,
            Self::Observed,
            Self::Proposed,
            Self::Approved,
            Self::Shadow,
            Self::Calibrated,
            Self::Advisory,
            Self::Enforced,
            Self::Structural,
            Self::Retired,
        ];
        for state in &states {
            complete(*state);
        }
        states
    }

    /// The rungs this one may advance to.
    ///
    /// NOTE on the two rungs with no retirement edge: `Structural` is terminal
    /// by construction -- a property made impossible by structure is not
    /// withdrawn by a policy act -- while `Calibrated`'s absence is asserted by
    /// no document. It is preserved as the published table had it rather than
    /// silently widened here; see #40.
    pub fn successors(self) -> &'static [Self] {
        match self {
            Self::Unknown => &[Self::Observed],
            Self::Observed => &[Self::Proposed],
            Self::Proposed => &[Self::Approved],
            Self::Approved => &[Self::Shadow, Self::Retired],
            Self::Shadow => &[Self::Calibrated, Self::Retired],
            Self::Calibrated => &[Self::Advisory],
            Self::Advisory => &[Self::Enforced, Self::Retired],
            Self::Enforced => &[Self::Structural, Self::Retired],
            Self::Structural | Self::Retired => &[],
        }
    }

    /// Whether advancing from this rung to `next` is structurally valid.
    pub fn may_advance_to(self, next: Self) -> bool {
        self.successors().contains(&next)
    }

    /// The strongest consequence a binding at this rung may apply.
    ///
    /// `None` means the binding applies no consequence at all: below `Shadow`
    /// it has not been evaluated on the real path, and once `Retired` it is out
    /// of service. This is where [`Consequence`] and the ladder meet --
    /// `Consequence::Advisory` is not the rung `Advisory`, it is the
    /// consequence that rung authorises, and rungs below it authorise less.
    pub fn max_consequence(self) -> Option<Consequence> {
        match self {
            Self::Unknown | Self::Observed | Self::Proposed | Self::Approved | Self::Retired => {
                None
            }
            Self::Shadow | Self::Calibrated => Some(Consequence::Informational),
            Self::Advisory => Some(Consequence::Advisory),
            Self::Enforced | Self::Structural => Some(Consequence::Deny),
        }
    }

    /// Whether a binding at this rung may apply `consequence`.
    pub fn authorises(self, consequence: Consequence) -> bool {
        self.max_consequence()
            .is_some_and(|strongest| consequence <= strongest)
    }
}

/// A transition the ladder does not permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IllegalTransition {
    /// The rung advanced from.
    pub from: HardeningState,
    /// The rung advanced to.
    pub to: HardeningState,
}

impl std::fmt::Display for IllegalTransition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?} may not advance to {:?}; progressive hardening has no shortcut",
            self.from, self.to
        )
    }
}

impl std::error::Error for IllegalTransition {}

/// A ladder position together with the path that reached it.
///
/// WHY the whole path rather than the current rung alone: the constitutional
/// claim of progressive hardening is not *where a binding is* but *that it got
/// there by climbing*. A single `state` field records the destination and
/// nothing else, so a binding deserialised straight into `Enforced` -- never
/// shadowed, never calibrated -- is indistinguishable from one that earned the
/// rung. Carrying the path makes the skip unrepresentable rather than merely
/// discouraged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct HardeningLadder {
    path: Vec<HardeningState>,
}

impl Default for HardeningLadder {
    fn default() -> Self {
        Self {
            path: vec![HardeningState::Unknown],
        }
    }
}

impl HardeningLadder {
    /// A ladder at its origin.
    pub fn new() -> Self {
        Self::default()
    }

    /// The rung currently occupied.
    pub fn current(&self) -> HardeningState {
        // INVARIANT: the path is never empty -- `new` seeds it and `TryFrom`
        // refuses an empty one -- so the last element always exists.
        self.path.last().copied().unwrap_or(HardeningState::Unknown)
    }

    /// The rungs climbed, in order, beginning at `Unknown`.
    pub fn history(&self) -> &[HardeningState] {
        &self.path
    }

    /// Climb to `next`.
    ///
    /// # Errors
    ///
    /// Returns [`IllegalTransition`] when the ladder does not permit the edge.
    pub fn advance(&mut self, next: HardeningState) -> Result<(), IllegalTransition> {
        let from = self.current();
        if from.may_advance_to(next) {
            self.path.push(next);
            Ok(())
        } else {
            Err(IllegalTransition { from, to: next })
        }
    }
}

/// A path that is not a legal climb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidLadder {
    /// The path was empty; every ladder begins at `Unknown`.
    Empty,
    /// The path began somewhere other than `Unknown`.
    WrongOrigin(HardeningState),
    /// The path contains an edge the ladder does not permit.
    Illegal(IllegalTransition),
}

impl std::fmt::Display for InvalidLadder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidLadder::Empty => {
                formatter.write_str("a hardening path is empty; every ladder begins at unknown")
            }
            InvalidLadder::WrongOrigin(state) => write!(
                formatter,
                "a hardening path begins at {state:?}; every ladder begins at unknown"
            ),
            InvalidLadder::Illegal(transition) => transition.fmt(formatter),
        }
    }
}

impl std::error::Error for InvalidLadder {}

impl TryFrom<Vec<HardeningState>> for HardeningLadder {
    type Error = InvalidLadder;

    fn try_from(path: Vec<HardeningState>) -> Result<Self, Self::Error> {
        let Some(origin) = path.first().copied() else {
            return Err(InvalidLadder::Empty);
        };
        if origin != HardeningState::Unknown {
            return Err(InvalidLadder::WrongOrigin(origin));
        }
        for pair in path.windows(2) {
            let (from, to) = (pair[0], pair[1]);
            if !from.may_advance_to(to) {
                return Err(InvalidLadder::Illegal(IllegalTransition { from, to }));
            }
        }
        Ok(Self { path })
    }
}

impl<'de> Deserialize<'de> for HardeningLadder {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let path = Vec::<HardeningState>::deserialize(deserializer)?;
        Self::try_from(path).map_err(serde::de::Error::custom)
    }
}

/// A consequence stronger than its rung authorises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnauthorizedConsequence {
    /// The rung the binding occupies.
    pub rung: HardeningState,
    /// The consequence it declared.
    pub consequence: Consequence,
}

impl std::fmt::Display for UnauthorizedConsequence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rung.max_consequence() {
            Some(strongest) => write!(
                formatter,
                "a binding at {:?} may apply at most {:?}, not {:?}",
                self.rung, strongest, self.consequence
            ),
            None => write!(
                formatter,
                "a binding at {:?} applies no consequence, so {:?} has no authority",
                self.rung, self.consequence
            ),
        }
    }
}

impl std::error::Error for UnauthorizedConsequence {}

/// A binding's blocking authority: the rung it climbed to, and the consequence
/// that rung lets it apply.
///
/// `docs/06-POLICY_COMPILER.md` puts it plainly -- blocking authority is a
/// property of the binding, not inherent in the detector. Pairing the two here
/// is what makes the ladder load-bearing rather than descriptive: there is no
/// way to hold a `Deny` without holding the climb that authorises it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BindingAuthority {
    hardening: HardeningLadder,
    consequence: Consequence,
}

/// A `BindingAuthority` that does not hold together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidAuthority {
    /// The climb itself is not legal.
    Ladder(InvalidLadder),
    /// The climb is legal but does not reach the declared consequence.
    Consequence(UnauthorizedConsequence),
    /// The advance is not a legal edge.
    Transition(IllegalTransition),
}

impl std::fmt::Display for InvalidAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidAuthority::Ladder(error) => error.fmt(formatter),
            InvalidAuthority::Consequence(error) => error.fmt(formatter),
            InvalidAuthority::Transition(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for InvalidAuthority {}

impl BindingAuthority {
    /// Pair a climb with the consequence it authorises.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuthority::Consequence`] when the rung reached does not
    /// authorise `consequence`.
    pub fn new(
        hardening: HardeningLadder,
        consequence: Consequence,
    ) -> Result<Self, InvalidAuthority> {
        let rung = hardening.current();
        if rung.authorises(consequence) {
            Ok(Self {
                hardening,
                consequence,
            })
        } else {
            Err(InvalidAuthority::Consequence(UnauthorizedConsequence {
                rung,
                consequence,
            }))
        }
    }

    /// The climb.
    pub fn hardening(&self) -> &HardeningLadder {
        &self.hardening
    }

    /// The consequence in force.
    pub fn consequence(&self) -> Consequence {
        self.consequence
    }

    /// Climb one rung, declaring the consequence that will hold there.
    ///
    /// WHY the consequence is an argument rather than carried across: a rung
    /// change can invalidate the consequence in either direction -- retiring a
    /// binding leaves `Deny` with nothing behind it, and promoting one is the
    /// whole point of climbing. Passing both makes the pair consistent at every
    /// instant instead of transiently wrong between two calls.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuthority::Transition`] when the edge is not legal, and
    /// [`InvalidAuthority::Consequence`] when the destination rung does not
    /// authorise `consequence`.
    pub fn advance(
        &mut self,
        next: HardeningState,
        consequence: Consequence,
    ) -> Result<(), InvalidAuthority> {
        if !next.authorises(consequence) {
            return Err(InvalidAuthority::Consequence(UnauthorizedConsequence {
                rung: next,
                consequence,
            }));
        }
        self.hardening
            .advance(next)
            .map_err(InvalidAuthority::Transition)?;
        self.consequence = consequence;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BindingAuthority {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            hardening: HardeningLadder,
            consequence: Consequence,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.hardening, wire.consequence).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn climb(states: &[HardeningState]) -> Result<HardeningLadder, InvalidLadder> {
        let mut path = vec![HardeningState::Unknown];
        path.extend_from_slice(states);
        HardeningLadder::try_from(path)
    }

    fn enforced() -> HardeningLadder {
        let mut ladder = HardeningLadder::new();
        for rung in [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
            HardeningState::Calibrated,
            HardeningState::Advisory,
            HardeningState::Enforced,
        ] {
            assert!(ladder.advance(rung).is_ok(), "{rung:?} is a legal rung");
        }
        ladder
    }

    #[test]
    fn a_new_ladder_stands_at_the_origin() {
        assert_eq!(HardeningLadder::new().current(), HardeningState::Unknown);
        assert_eq!(HardeningLadder::new().history(), [HardeningState::Unknown]);
    }

    #[test]
    fn the_full_climb_reaches_structural() {
        let mut ladder = enforced();
        assert!(ladder.advance(HardeningState::Structural).is_ok());
        assert_eq!(ladder.current(), HardeningState::Structural);
    }

    #[test]
    fn a_skipped_rung_is_refused() {
        // The whole content of "progressive hardening": arriving at enforcement
        // without shadowing or calibrating is the thing the ladder forbids.
        let mut ladder = HardeningLadder::new();
        assert_eq!(
            ladder.advance(HardeningState::Enforced),
            Err(IllegalTransition {
                from: HardeningState::Unknown,
                to: HardeningState::Enforced,
            })
        );
    }

    #[test]
    fn a_forged_history_is_refused() {
        // The deserialisation direction, which is the one an untrusted document
        // takes. A path is checked edge by edge, not merely for a legal endpoint.
        assert_eq!(
            climb(&[HardeningState::Enforced]),
            Err(InvalidLadder::Illegal(IllegalTransition {
                from: HardeningState::Unknown,
                to: HardeningState::Enforced,
            }))
        );
    }

    #[test]
    fn a_ladder_must_begin_at_the_origin() {
        assert_eq!(
            HardeningLadder::try_from(vec![HardeningState::Shadow, HardeningState::Calibrated]),
            Err(InvalidLadder::WrongOrigin(HardeningState::Shadow))
        );
        assert_eq!(
            HardeningLadder::try_from(Vec::new()),
            Err(InvalidLadder::Empty)
        );
    }

    #[test]
    fn every_rung_reachable_from_the_origin_is_reachable_by_climbing() {
        // A rung the table can never reach is a rung that exists only on paper.
        // Structural and Retired are terminal, so this walks forward only.
        let mut reached = vec![HardeningState::Unknown];
        let mut frontier = vec![HardeningState::Unknown];
        while let Some(state) = frontier.pop() {
            for next in state.successors() {
                if !reached.contains(next) {
                    reached.push(*next);
                    frontier.push(*next);
                }
            }
        }
        for state in HardeningState::all() {
            assert!(
                reached.contains(&state),
                "{state:?} is declared but unreachable from the origin"
            );
        }
    }

    #[test]
    fn the_declared_order_of_consequence_is_its_severity_order() {
        // `authorises` compares consequences with `<=`, which derives its
        // meaning from declaration order. Reordering the variants would silently
        // redefine what every rung permits, so the order is asserted rather than
        // assumed.
        assert!(Consequence::Informational < Consequence::Advisory);
        assert!(Consequence::Advisory < Consequence::RequireReview);
        assert!(Consequence::RequireReview < Consequence::Deny);
    }

    #[test]
    fn a_rung_below_shadow_authorises_nothing() {
        for rung in [
            HardeningState::Unknown,
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Retired,
        ] {
            assert_eq!(rung.max_consequence(), None, "{rung:?}");
            assert!(
                !rung.authorises(Consequence::Informational),
                "{rung:?} must not authorise even the weakest consequence"
            );
        }
    }

    #[test]
    fn shadow_records_and_does_not_advise() {
        assert!(HardeningState::Shadow.authorises(Consequence::Informational));
        assert!(!HardeningState::Shadow.authorises(Consequence::Advisory));
    }

    #[test]
    fn advisory_advises_and_does_not_block() {
        assert!(HardeningState::Advisory.authorises(Consequence::Advisory));
        assert!(!HardeningState::Advisory.authorises(Consequence::RequireReview));
        assert!(!HardeningState::Advisory.authorises(Consequence::Deny));
    }

    #[test]
    fn only_an_enforced_binding_blocks() {
        for rung in HardeningState::all() {
            let blocks = rung.authorises(Consequence::Deny);
            let expected = matches!(rung, HardeningState::Enforced | HardeningState::Structural);
            assert_eq!(blocks, expected, "{rung:?}");
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be built is a broken test, not a finding"
    )]
    fn a_consequence_beyond_the_rung_cannot_be_paired_with_it() {
        let shadow = climb(&[
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
        ])
        .expect("a shadow climb is legal");
        assert_eq!(
            BindingAuthority::new(shadow, Consequence::Deny),
            Err(InvalidAuthority::Consequence(UnauthorizedConsequence {
                rung: HardeningState::Shadow,
                consequence: Consequence::Deny,
            }))
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be built is a broken test, not a finding"
    )]
    fn retiring_an_enforcing_binding_must_drop_its_consequence() {
        let mut authority = BindingAuthority::new(enforced(), Consequence::Deny)
            .expect("an enforced binding may deny");
        assert!(
            authority
                .advance(HardeningState::Retired, Consequence::Deny)
                .is_err(),
            "a retired binding has nothing standing behind a denial"
        );
        assert_eq!(
            authority.consequence(),
            Consequence::Deny,
            "a refused advance must leave the authority untouched"
        );
    }

    #[test]
    fn a_forged_authority_does_not_survive_the_wire() {
        // The path an untrusted policy bundle takes. Both halves are checked:
        // the climb, and the consequence the climb reaches.
        let skipped = serde_json::json!({
            "hardening": ["unknown", "enforced"],
            "consequence": "Deny",
        });
        assert!(serde_json::from_value::<BindingAuthority>(skipped).is_err());

        let overreaching = serde_json::json!({
            "hardening": ["unknown", "observed", "proposed", "approved", "shadow"],
            "consequence": "Deny",
        });
        assert!(serde_json::from_value::<BindingAuthority>(overreaching).is_err());
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot serialize is a broken test, not a finding"
    )]
    fn a_legal_authority_round_trips() {
        let authority = BindingAuthority::new(enforced(), Consequence::Deny)
            .expect("an enforced binding may deny");
        let text = serde_json::to_string(&authority).expect("an authority serialises");
        assert_eq!(
            serde_json::from_str::<BindingAuthority>(&text).expect("and deserialises"),
            authority
        );
        assert!(
            text.contains(r#""hardening":["unknown","observed""#),
            "the climb is emitted as its path, not as an object: {text}"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot serialize is a broken test, not a finding"
    )]
    fn the_projection_has_a_distinct_token_for_every_rung() {
        // The published table is keyed by serde token. The exhaustive match in
        // `all()` catches a rung added and never listed; it cannot catch a rung
        // listed twice, nor two rungs renamed onto one token -- and either would
        // publish a table shorter than the enum with nothing failing.
        let mut tokens: Vec<String> = HardeningState::all()
            .into_iter()
            .map(|state| serde_json::to_string(&state).expect("a rung serialises"))
            .collect();
        let declared = tokens.len();
        tokens.sort();
        tokens.dedup();
        assert_eq!(
            tokens.len(),
            declared,
            "two rungs share a token or one is listed twice: {tokens:?}"
        );
    }

    #[test]
    fn every_successor_is_a_declared_rung() {
        let declared = HardeningState::all();
        for state in &declared {
            for next in state.successors() {
                assert!(
                    declared.contains(next),
                    "{state:?} names {next:?} as a successor, but `all()` omits it"
                );
            }
        }
    }
}
