# Formal models

The TLA+ models, the configurations they are checked under, and the planted
defects that keep the checker honest. CI runs all of it on every pull request,
discovering the modules from the directory rather than from a list here.

This file exists to state the boundary between what the models establish and
what they do not. A green model-checking run is a narrow claim, and the way it
gets misread is by being quoted without its configuration.

## What is here

| Path | What it is |
|---|---|
| `Delegation.tla` / `.cfg` | Monotonic delegation: a grant may narrow its parent on every authority axis, never exceed it. |
| `Workflow.tla` / `.cfg` | The protected-operation path: authorization, budget reservation, single-use lease, execution, the evidence states that follow it, denial, and retry. |
| `EffectAmbiguity.tla` / `.cfg` | Ambiguous effect execution: delivery state, execution outcome, epistemic resolution and replay disposition as four separate facts, with reconciliation and compensation. |
| `EffectAmbiguityIdempotentTarget.tla` / `.cfg` | The same model under `TargetEnforcesIdempotency = TRUE`, where the easiest ground for replay is always available and the other rules have to hold anyway. |
| `negative/*.tla` / `.cfg` | Specifications with a planted defect. **CI requires the checker to reject each one.** |

## Model-to-Rust correspondence

The models are abstractions of `politeia-core`, not translations of it. Each
construct below stands for a Rust item, and the abstraction it performs is the
thing to weigh when reading a result.

| Model | Rust | What the abstraction drops |
|---|---|---|
| `SubsetGrant` | `Delegation::is_attenuation_of` | Nothing structural: both compare the same seven axes with the same relations. |
| `NarrowsCap` | the `narrows` closure in `ResourceBudget::is_attenuation_of` | Nothing. |
| one `cap` axis | six budget caps | **Five of six caps.** They are six instances of one rule, so the model checks the rule once. That every field actually uses it is a property of the implementation, established by `crates/politeia-core/src/attenuation_properties.rs`. |
| `actions`, `resources`, `effects`, `dataClasses`, `audience` | the matching `BTreeSet` fields | Element identity. The model uses model values; the Rust types use strings and enums, one of which (`DataClass::ClientRestricted`) carries a payload that participates in equality. |
| `expiresAt` in `0..MaxExpiry` | `expires_at: jiff::Timestamp` | Real time. The model needs only an order. |
| `grants` as a set | the trusted delegation registry | Identity and issuer/subject linkage. `DispatcherConfig::new` enforces those separately, and they are not width axes. |
| `Workflow`'s `state`, `authorized`, `reserved`, `leased`, `denied` | the dispatcher's authorize / reserve / lease / execute path | Identity. The model records *that* each step happened, not *which* delegation, budget or lease it happened against. Exactness of those bindings is tested in `politeia-runtime`, not modelled. |
| `EffectAmbiguity`'s `delivery`, `outcome`, `resolution`, `replay` | the rules in `docs/11-FAILURE_SEMANTICS.md` | **Everything below the rules.** There is no Rust counterpart yet: the effect state machine this constrains is unimplemented, and the document requires it to define legal ambiguity and reconciliation transitions before the disconnected path is built. This model is that definition, ahead of the code rather than behind it. |
| `overlap` | the canonical effect-subject derivation | The derivation itself. The model has a three-valued answer -- no overlap, overlaps, uncertain -- and says nothing about how a subject is derived from target, operation, resources and normalized parameters. |

## What the models do not cover

Stated plainly, because the gaps are larger than the coverage and a reader who
assumes otherwise will over-trust a green run.

- **Concurrency.** Replay is modelled as a sequential retry of one intent. Two
  dispatchers racing for the same lease is a different question, and the ledger
  tests in `politeia-runtime` are what cover it.
- **Exactness of binding.** `Workflow` records *that* an operation was
  authorized, reserved and leased -- not *which* delegation, budget or lease it
  was bound to. "No effect without a lease" is modelled; "no effect except under
  the exact lease issued for this intent" is not, and that is the substance of
  REQ-02. `crates/politeia-runtime/src/tests/replay.rs` tests it.
- **Expiry and revocation as events.** Expiry is an ordered value compared at
  issuance. Nothing models a grant expiring *during* a run, or being revoked.
- **Nested reauthorization.** Not modelled anywhere.
- **A reissue's own outcome.** `EffectAmbiguity` covers one effect subject
  through one ambiguity episode and the grounded reissue that follows it. The
  reissue's resolution is out of scope: `resolution`, `receiptBound`,
  `targetObserved` and `reconciled` are facts about the subject, not about an
  attempt, and nothing resets them. A model of successive independent episodes
  would need them per-attempt.
- **The six budget caps individually**, as above.

## What the bounded configurations mean

Both models are checked under **bounded** configurations, not exhaustively over
their intended domains.

`Delegation` caps the grant set at two. That is sufficient for `Monotonic`,
which relates each grant to its direct parent and therefore forms every pair it
can check from a root and one child. It is **not** sufficient to observe a
defect that requires a longer chain, and one such defect exists: see
`negative/SlackCap.tla`, whose planted rule is admissible at every single step
and violated across three. Root-to-leaf attenuation is recovered by checking
that the narrowing relation is transitive — `NarrowsCapIsTransitive`, exhaustive
over the modelled cap domain — rather than by exploring deep chains.

Every constant set is a single element. That is the smallest configuration in
which each axis can still be widened, and widening is what the invariants exist
to refuse. **The sets must stay non-empty**: `EveryAxisIsChecked` widens each
axis to its full constant, so an empty constant makes that widening a no-op and
the assertion would pass while testing nothing.

## Why `negative/` exists

A checking step that has only ever run against specifications which satisfy
their invariants has not demonstrated that it can report a violation. It goes
green against an invariant written as `TRUE`, against a `.cfg` naming no
invariant, and against a checker that never executed.

This repository has had two of those three. `Workflow.tla`'s safety property
was literally `... => TRUE`, and `Delegation.tla` aborted on a type error
before evaluating any invariant — both while shipping as assurance artifacts
carrying `THEOREM`s.

So each planted defect is checked in and CI requires a rejection:

| Module | Defect | The one invariant that fails |
|---|---|---|
| `UnauthorizedWorkflow` | runs with a reservation and lease but no authorization | `NeverExecutesUnauthorized` |
| `SkippedReservation` | leases and runs without committing a budget | `NeverExecutesWithoutReservation` |
| `SkippedLease` | runs on a reservation with no lease issued | `NeverExecutesWithoutLease` |
| `ResurrectedDenial` | a retry carries a denied operation into execution | `DenialIsFinal` |
| `DoubleSpentLease` | a retry re-presents a lease without checking whether it is spent | `AtMostOneEffectPerLease` |
| `UncheckedAxis` | `dataClasses` dropped from the narrowing rule | `EveryAxisIsChecked` |
| `SlackCap` | one unit of cap slack against a positive parent cap | `NarrowsCapIsTransitive` |
| `UnattenuatedChild` | a child admitted without narrowing at all | `Monotonic` |
| `UnspentLeaseEffect` | an effect that runs without spending its lease | `EffectsRequireASpentLease` |
| `AcknowledgedMeansRan` | acknowledgement written as an execution outcome | `OutcomeRequiresEvidence` |
| `UnresolvedReadsAsNotRun` | evidence gathered, an outcome recorded, resolution never reached | `UnresolvedIsNotAnOutcome` |
| `LocalKeyGrantsReplay` | a locally minted identifier treated as grounds for replay | `ReplayNeedsGrounds` |
| `UntestedOverlapReplay` | replay granted before the overlap test has run | `UntestedEquivalenceBlocksReplay` |
| `UncertainOverlapReplay` | replay granted while equivalence is uncertain | `UncertainEquivalenceBlocksReplay` |
| `ReconciliationRunsTheEffect` | a read-only reconciliation that produces an effect | `EveryReissueHadAGrant` |
| `RevisedOutcome` | a second source overwriting an established outcome | `CompensationFollowsResolution` |
| `CompensationWithoutResolution` | compensating an effect nobody established ran | `CompensationFollowsResolution` |

Each `.cfg` lists **every** invariant, not only the one expected to fail, so the
others passing is part of the recorded result. CI checks that too: a fixture
whose configuration omits the invariant it targets can still be rejected by some
*other* invariant, and would then isolate nothing while looking correct. That is
not hypothetical -- it happened while these were being written, when a substring
guard matched an invariant's name in a comment and skipped declaring it.

The last column is the point. Each defect is caught by **exactly one** invariant
and passes the rest, so each invariant is shown to do work no other one does.

CI enforces the converse: **every declared invariant must be the reported
violation of some fixture.** An invariant no planted defect can make fire has not
been shown to constrain anything, and two kinds end up there, both looking
exactly like working checks -- one implied by a stronger invariant beside it, and
one the model maintains by construction so no reachable state can negate it.
`TypeOK` is exempt, being a well-formedness claim about the model rather than
about the system.

Note that two fixtures share `CompensationFollowsResolution`. That is the
allowed direction: an invariant may catch several defects, but a defect caught by
two invariants at once isolates neither.

The pass condition for a fixture is a **reported violation**, not a non-zero
exit. TLC exits non-zero for a parse error, a missing module, a bad
configuration, and an aborted run -- and it aborts when two runs share a scratch
directory, which it names after the current second. These models check in well
under a second. Reading the exit code alone made a crashed run indistinguishable
from a caught defect, and the step said so in green. Each run now gets its own
`-metadir` and must name the invariant it violated.

Most fixtures `EXTENDS` the model they mirror and add a single disjunct, so they
cannot drift from it -- CI passes `-DTLA-Library=..` to resolve it. That is only
available because those defects are *additive*. A defect that removes or weakens
a definition cannot be written as an extension, which is why `UncheckedAxis` and
`SlackCap` are full copies and have to be read as such.

The negative step discovers these modules rather than naming them, and fails when
it finds none.

## Running them

CI does this on every pull request, with the checker pinned by release tag and
verified by digest. To reproduce:

```sh
curl -fsSLo tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
cd formal
for module in *.tla; do
  name="${module%.tla}"
  java -cp ../tla2tools.jar tlc2.TLC \
    -metadir "/tmp/tlc/${name}" -config "${name}.cfg" "${module}"
done
```

`-metadir` keeps TLC's per-run state and fingerprint files out of the tree, and
keeps two runs from colliding on the directory it names after the current
second. Without it those files land in a `states/` directory beside whichever
module was checked; they are output rather than source and are ignored.
