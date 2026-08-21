//! Generated evidence that widening any single authority axis breaks attenuation.
//!
//! The example tests beside these prove that particular narrowings hold and that
//! two particular widenings are refused. What they cannot show is that the
//! remaining axes are checked at all, and an axis nobody exercises is exactly
//! where an authority bypass survives review: every neighbouring field is exact,
//! the tests are green, and the one unchecked field is load-bearing.
//!
//! So the shape here is one property per axis, each mutating exactly that axis
//! and nothing else, over generated parents rather than a fixture. A widening
//! that only fails because two axes moved together would prove nothing about
//! either.

use std::collections::BTreeSet;

use jiff::Timestamp;
use proptest::prelude::*;

use crate::{DataClass, Delegation, DelegationId, Effect, PrincipalId, ResourceBudget};

/// The effect held back from every generated parent, so widening always has a
/// member available that the parent provably lacks.
const RESERVED_EFFECT: Effect = Effect::ChangeAuthorization;

/// The data class held back from every generated parent, for the same reason.
fn reserved_data_class() -> DataClass {
    DataClass::ClientRestricted("reserved-for-widening".to_owned())
}

/// A name no generator produces, so adding it to any string set widens it.
const RESERVED_NAME: &str = "reserved-for-widening";

/// Every effect a generated parent may hold. `RESERVED_EFFECT` is absent by
/// construction.
const GENERATED_EFFECTS: &[Effect] = &[
    Effect::ReadFilesystem,
    Effect::WriteFilesystem,
    Effect::SpawnProcess,
    Effect::NetworkEgress,
    Effect::ReadSecret,
    Effect::WriteSecret,
    Effect::ReadExternalSystem,
    Effect::WriteExternalSystem,
    Effect::CreateArtifact,
];

/// An authority axis: one dimension along which a child could exceed its parent.
///
/// Kept as an enum rather than a list of closures so that the exhaustiveness
/// guards below can name each one, and so a failing case reports which axis it
/// widened rather than which generated value it happened to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Axis {
    Actions,
    Resources,
    Effects,
    DataClasses,
    Audience,
    ExpiresAt,
    BudgetWallMs,
    BudgetCpuMs,
    BudgetMemoryBytes,
    BudgetIoBytes,
    BudgetNetworkBytes,
    BudgetExternalCost,
}

impl Axis {
    const ALL: &'static [Axis] = &[
        Axis::Actions,
        Axis::Resources,
        Axis::Effects,
        Axis::DataClasses,
        Axis::Audience,
        Axis::ExpiresAt,
        Axis::BudgetWallMs,
        Axis::BudgetCpuMs,
        Axis::BudgetMemoryBytes,
        Axis::BudgetIoBytes,
        Axis::BudgetNetworkBytes,
        Axis::BudgetExternalCost,
    ];
}

/// Force a decision about every `Delegation` field.
///
/// WHY a destructuring with no `..`: adding a field to `Delegation` stops this
/// compiling until someone classifies it as authority width or as identity. The
/// alternative — a hand-kept axis list — goes stale silently, and the failure it
/// produces is a new field that no property ever widens. That is the precise
/// defect this module exists to make impossible.
fn delegation_width_axes(delegation: &Delegation) -> Vec<Axis> {
    let Delegation {
        // Identity and chain linkage. These are checked for exact equality and
        // parentage elsewhere; widening is not meaningful for them.
        id: _,
        issuer: _,
        subject: _,
        parent: _,
        // Authority width.
        actions: _,
        resources: _,
        effects: _,
        data_classes: _,
        audience: _,
        expires_at: _,
        budget: _,
    } = delegation;

    let mut axes = vec![
        Axis::Actions,
        Axis::Resources,
        Axis::Effects,
        Axis::DataClasses,
        Axis::Audience,
        Axis::ExpiresAt,
    ];
    axes.extend(budget_width_axes(&delegation.budget));
    axes
}

/// Force the same decision about every `ResourceBudget` field.
fn budget_width_axes(budget: &ResourceBudget) -> Vec<Axis> {
    let ResourceBudget {
        wall_ms: _,
        cpu_ms: _,
        memory_bytes: _,
        io_bytes: _,
        network_bytes: _,
        external_cost_microunits: _,
    } = budget;

    vec![
        Axis::BudgetWallMs,
        Axis::BudgetCpuMs,
        Axis::BudgetMemoryBytes,
        Axis::BudgetIoBytes,
        Axis::BudgetNetworkBytes,
        Axis::BudgetExternalCost,
    ]
}

/// Widen exactly one axis, leaving every other byte of the delegation alone.
fn widen(parent: &Delegation, axis: Axis) -> Delegation {
    let mut child = parent.clone();
    match axis {
        Axis::Actions => {
            child.actions.insert(RESERVED_NAME.to_owned());
        }
        Axis::Resources => {
            child.resources.insert(RESERVED_NAME.to_owned());
        }
        Axis::Effects => {
            child.effects.insert(RESERVED_EFFECT);
        }
        Axis::DataClasses => {
            child.data_classes.insert(reserved_data_class());
        }
        Axis::Audience => {
            child.audience.insert(RESERVED_NAME.to_owned());
        }
        Axis::ExpiresAt => {
            child.expires_at = later_than(parent.expires_at);
        }
        Axis::BudgetWallMs => raise(&mut child.budget.wall_ms),
        Axis::BudgetCpuMs => raise(&mut child.budget.cpu_ms),
        Axis::BudgetMemoryBytes => raise(&mut child.budget.memory_bytes),
        Axis::BudgetIoBytes => raise(&mut child.budget.io_bytes),
        Axis::BudgetNetworkBytes => raise(&mut child.budget.network_bytes),
        Axis::BudgetExternalCost => raise(&mut child.budget.external_cost_microunits),
    }
    child
}

/// Remove one budget cap the parent imposed, which is the other way to exceed it.
///
/// WHY separate from `widen`: an uncapped child under a capped parent is not a
/// larger number, it is the absence of a number, and the two travel through
/// different arms of the narrowing rule. A suite that only ever raised values
/// would leave the `(None, Some(_))` arm unexercised.
fn uncap(parent: &Delegation, axis: Axis) -> Option<Delegation> {
    let mut child = parent.clone();
    let field = match axis {
        Axis::BudgetWallMs => &mut child.budget.wall_ms,
        Axis::BudgetCpuMs => &mut child.budget.cpu_ms,
        Axis::BudgetMemoryBytes => &mut child.budget.memory_bytes,
        Axis::BudgetIoBytes => &mut child.budget.io_bytes,
        Axis::BudgetNetworkBytes => &mut child.budget.network_bytes,
        Axis::BudgetExternalCost => &mut child.budget.external_cost_microunits,
        _ => return None,
    };
    if field.is_none() {
        // The parent imposed no cap here, so there is nothing to remove and no
        // widening to test.
        return None;
    }
    *field = None;
    Some(child)
}

fn raise(field: &mut Option<u64>) {
    *field = Some(field.map_or(0, |value| value.saturating_add(1)));
}

fn later_than(instant: Timestamp) -> Timestamp {
    Timestamp::from_second(instant.as_second().saturating_add(1)).unwrap_or(Timestamp::MAX)
}

// --- Generators -------------------------------------------------------------

fn arb_name() -> impl Strategy<Value = String> {
    "[a-z]{1,8}".prop_map(|name| format!("generated-{name}"))
}

fn arb_names() -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set(arb_name(), 0..4)
}

fn arb_effects() -> impl Strategy<Value = BTreeSet<Effect>> {
    prop::collection::btree_set(prop::sample::select(GENERATED_EFFECTS), 0..4)
}

fn arb_data_classes() -> impl Strategy<Value = BTreeSet<DataClass>> {
    let simple = prop::sample::select(vec![
        DataClass::Public,
        DataClass::Internal,
        DataClass::Confidential,
        DataClass::Secret,
        DataClass::Regulated,
        DataClass::Personal,
        DataClass::Health,
        DataClass::Financial,
    ]);
    let restricted = arb_name().prop_map(DataClass::ClientRestricted);
    prop::collection::btree_set(prop_oneof![simple, restricted], 0..4)
}

/// A budget whose values leave room to be raised without saturating.
fn arb_budget() -> impl Strategy<Value = ResourceBudget> {
    let cap = prop::option::of(0u64..1_000_000);
    (
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap,
    )
        .prop_map(
            |(wall_ms, cpu_ms, memory_bytes, io_bytes, network_bytes, external_cost_microunits)| {
                ResourceBudget {
                    wall_ms,
                    cpu_ms,
                    memory_bytes,
                    io_bytes,
                    network_bytes,
                    external_cost_microunits,
                }
            },
        )
}

/// A budget with every cap present, so every cap can be removed.
fn arb_fully_capped_budget() -> impl Strategy<Value = ResourceBudget> {
    let cap = 0u64..1_000_000;
    (
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap.clone(),
        cap,
    )
        .prop_map(
            |(wall_ms, cpu_ms, memory_bytes, io_bytes, network_bytes, external_cost_microunits)| {
                ResourceBudget {
                    wall_ms: Some(wall_ms),
                    cpu_ms: Some(cpu_ms),
                    memory_bytes: Some(memory_bytes),
                    io_bytes: Some(io_bytes),
                    network_bytes: Some(network_bytes),
                    external_cost_microunits: Some(external_cost_microunits),
                }
            },
        )
}

fn arb_delegation_with(
    budget: impl Strategy<Value = ResourceBudget>,
) -> impl Strategy<Value = Delegation> {
    (
        arb_names(),
        arb_names(),
        arb_effects(),
        arb_data_classes(),
        arb_names(),
        0i64..4_000_000_000,
        budget,
    )
        .prop_map(
            |(actions, resources, effects, data_classes, audience, second, budget)| Delegation {
                id: DelegationId::new(),
                issuer: PrincipalId::new(),
                subject: PrincipalId::new(),
                parent: None,
                actions,
                resources,
                effects,
                data_classes,
                audience,
                expires_at: Timestamp::from_second(second).unwrap_or(Timestamp::UNIX_EPOCH),
                budget,
            },
        )
}

fn arb_delegation() -> impl Strategy<Value = Delegation> {
    arb_delegation_with(arb_budget())
}

fn arb_axis() -> impl Strategy<Value = Axis> {
    prop::sample::select(Axis::ALL)
}

fn arb_budget_axis() -> impl Strategy<Value = Axis> {
    prop::sample::select(vec![
        Axis::BudgetWallMs,
        Axis::BudgetCpuMs,
        Axis::BudgetMemoryBytes,
        Axis::BudgetIoBytes,
        Axis::BudgetNetworkBytes,
        Axis::BudgetExternalCost,
    ])
}

// --- Properties -------------------------------------------------------------

proptest! {
    /// Positive control. Without it, every negative property below would also
    /// pass against an `is_attenuation_of` that simply returned false.
    #[test]
    fn an_identical_child_attenuates(parent in arb_delegation()) {
        let child = parent.clone();
        prop_assert!(
            child.is_attenuation_of(&parent),
            "a child identical to its parent must attenuate it"
        );
    }

    /// Widening exactly one axis, over generated parents, must be refused —
    /// whichever axis it is.
    ///
    /// The parent is fully capped on purpose. Raising a budget cap is only a
    /// widening when the parent imposed one: under an uncapped parent every
    /// value narrows, which the property below asserts in its own right.
    #[test]
    fn widening_one_axis_breaks_attenuation(
        parent in arb_delegation_with(arb_fully_capped_budget()),
        axis in arb_axis(),
    ) {
        let child = widen(&parent, axis);
        prop_assert!(
            !child.is_attenuation_of(&parent),
            "widening {axis:?} was accepted as an attenuation"
        );
    }

    /// An uncapped parent is narrowed by any cap at all, on every budget axis.
    ///
    /// This asymmetry is the `(_, None) => true` arm of the narrowing rule, and
    /// it is easy to read as a bug in the direction of permissiveness. It is
    /// not: a parent that imposed no limit cannot be exceeded by a child that
    /// imposes one. Asserting it keeps a later reader from "fixing" the arm and
    /// making every capped child of an unbounded parent unusable.
    #[test]
    fn any_cap_narrows_an_uncapped_parent(
        parent in arb_delegation_with(Just(ResourceBudget {
            wall_ms: None,
            cpu_ms: None,
            memory_bytes: None,
            io_bytes: None,
            network_bytes: None,
            external_cost_microunits: None,
        })),
        axis in arb_budget_axis(),
        cap in 0u64..1_000_000,
    ) {
        let mut child = parent.clone();
        match axis {
            Axis::BudgetWallMs => child.budget.wall_ms = Some(cap),
            Axis::BudgetCpuMs => child.budget.cpu_ms = Some(cap),
            Axis::BudgetMemoryBytes => child.budget.memory_bytes = Some(cap),
            Axis::BudgetIoBytes => child.budget.io_bytes = Some(cap),
            Axis::BudgetNetworkBytes => child.budget.network_bytes = Some(cap),
            Axis::BudgetExternalCost => child.budget.external_cost_microunits = Some(cap),
            other => return Err(TestCaseError::fail(format!("not a budget axis: {other:?}"))),
        }
        prop_assert!(
            child.is_attenuation_of(&parent),
            "capping {axis:?} under an uncapped parent must narrow, not widen"
        );
    }

    /// Removing a cap the parent imposed exceeds it just as raising one does,
    /// through a different arm of the rule.
    #[test]
    fn uncapping_one_budget_axis_breaks_attenuation(
        parent in arb_delegation_with(arb_fully_capped_budget()),
        axis in arb_budget_axis(),
    ) {
        let child = uncap(&parent, axis).ok_or_else(|| {
            TestCaseError::fail("a fully capped parent must have a cap to remove")
        })?;
        prop_assert!(
            !child.is_attenuation_of(&parent),
            "removing the {axis:?} cap was accepted as an attenuation"
        );
    }

    /// A widening on one axis is not excused by narrowing every other axis.
    ///
    /// This is the interaction the example tests cannot reach: each axis is
    /// checked independently, so a conjunction that happened to be evaluated
    /// lazily, or a rule that compared budgets as a whole, would pass every
    /// single-axis property above and fail here.
    #[test]
    fn narrowing_everything_else_does_not_excuse_one_widening(
        parent in arb_delegation_with(arb_fully_capped_budget()),
        axis in arb_axis(),
    ) {
        let mut child = widen(&parent, axis);
        // Narrow every set to empty and pull expiry back, except the widened axis.
        if axis != Axis::Actions { child.actions.clear(); }
        if axis != Axis::Resources { child.resources.clear(); }
        if axis != Axis::Effects { child.effects.clear(); }
        if axis != Axis::DataClasses { child.data_classes.clear(); }
        if axis != Axis::Audience { child.audience.clear(); }
        if axis != Axis::ExpiresAt {
            child.expires_at = Timestamp::UNIX_EPOCH;
        }

        prop_assert!(
            !child.is_attenuation_of(&parent),
            "widening {axis:?} was excused by narrowing the other axes"
        );
    }
}

// --- Coverage ledger --------------------------------------------------------

#[test]
fn every_width_axis_is_named_and_exercised() {
    // The properties above take an arbitrary axis, so what they cover is exactly
    // `Axis::ALL`. This asserts that set is the same one the exhaustive
    // destructuring produces — otherwise a field could be classified as width
    // and still never be widened by any property.
    let sample = Delegation {
        id: DelegationId::new(),
        issuer: PrincipalId::new(),
        subject: PrincipalId::new(),
        parent: None,
        actions: BTreeSet::new(),
        resources: BTreeSet::new(),
        effects: BTreeSet::new(),
        data_classes: BTreeSet::new(),
        audience: BTreeSet::new(),
        expires_at: Timestamp::UNIX_EPOCH,
        budget: ResourceBudget {
            wall_ms: None,
            cpu_ms: None,
            memory_bytes: None,
            io_bytes: None,
            network_bytes: None,
            external_cost_microunits: None,
        },
    };

    let classified: BTreeSet<Axis> = delegation_width_axes(&sample).into_iter().collect();
    let exercised: BTreeSet<Axis> = Axis::ALL.iter().copied().collect();
    assert_eq!(
        classified, exercised,
        "an axis is classified as authority width but never widened by any property"
    );
}

#[test]
fn the_reserved_widening_members_are_absent_from_every_generated_parent() {
    // Widening relies on holding one member back. If a generator ever produced
    // it, `widen` would leave the set unchanged and the property would pass
    // while testing nothing — the quiet failure this whole module is about.
    assert!(
        !GENERATED_EFFECTS.contains(&RESERVED_EFFECT),
        "the reserved effect must not be generatable"
    );
    assert!(
        RESERVED_NAME.starts_with("reserved-"),
        "the reserved name must not collide with the generated- prefix"
    );
    match reserved_data_class() {
        DataClass::ClientRestricted(name) => assert_eq!(name, RESERVED_NAME),
        other => panic!("the reserved data class must stay client-restricted, got {other:?}"),
    }
}
