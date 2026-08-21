----------------------------- MODULE Authority -----------------------------
EXTENDS Naturals

\* Authority as a claim about a moment and a scope, and what happens when
\* either lapses.
\*
\* `Workflow.tla` treats expiry as a value compared once, at issuance. That is
\* the easy half. The hard half is that time passes between issuing a lease and
\* using it -- `politeia-runtime`'s ledger owns the clock and rechecks expiry
\* inside the same atomic boundary that claims the reservation, precisely
\* because a lease valid when minted may not be valid when spent. Nothing
\* modelled that, so nothing could distinguish a system that rechecks from one
\* that trusts its own earlier answer.
\*
\* Three lapses share one shape here: an authority can run out (expiry), be
\* withdrawn (revocation), or be derived from one that did either (nested
\* reauthorization). In every case the authorization was true when it was made
\* and is not true now, and the question is whether anything notices.

\* The clock. Bounded, and the only thing that advances on its own.
CONSTANT MaxTime

\* When the outer delegation's authority ends. Strictly inside the clock's
\* range so that both sides of expiry are reachable: an expiry at or beyond
\* MaxTime would make every state unexpired and every invariant about expiry
\* vacuously true.
CONSTANT OuterExpiry

\* How many effect invocations to explore, across both authorities.
CONSTANT MaxEffects

\* The moment a revocation that never happened would have happened: one tick
\* past the horizon, so it is later than every real one.
\*
\* WHY a sentinel moment rather than a distinct `Never` value: TLC evaluates
\* both sides of a disjunction, so `revokedAt = Never \/ clock < revokedAt`
\* still reaches the comparison and fails on a model value that is not an
\* integer. Guarding every such site is a rule to remember at each one. Keeping
\* the variable an integer throughout removes the site instead.
NeverRevoked == MaxTime + 1

VARIABLES clock, revokedAt,
          outerLeased, innerLeased, innerExpiry,
          effects, latestEffectAt,
          innerEffects, latestInnerEffectAt,
          everExecuted

vars == <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
          effects, latestEffectAt, innerEffects, latestInnerEffectAt,
          everExecuted>>

\* The outer authority is live when time has not passed its expiry and nobody
\* has withdrawn it.
OuterLive == /\ clock < OuterExpiry
             /\ clock < revokedAt

Init ==
    /\ clock = 0
    /\ revokedAt = NeverRevoked
    /\ outerLeased = FALSE
    /\ innerLeased = FALSE
    /\ innerExpiry = 0
    /\ effects = 0
    /\ latestEffectAt = 0
    /\ innerEffects = 0
    /\ latestInnerEffectAt = 0
    /\ everExecuted = FALSE

\* Time passes whether or not anything is using it. This is the whole reason
\* the model exists: every guard below is evaluated against `clock`, not
\* against the clock as it stood when the lease was issued.
Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED <<revokedAt, outerLeased, innerLeased, innerExpiry,
                   effects, latestEffectAt, innerEffects, latestInnerEffectAt,
                   everExecuted>>

Revoke ==
    /\ revokedAt = NeverRevoked
    /\ revokedAt' = clock
    /\ UNCHANGED <<clock, outerLeased, innerLeased, innerExpiry,
                   effects, latestEffectAt, innerEffects, latestInnerEffectAt,
                   everExecuted>>

IssueOuterLease ==
    /\ ~outerLeased
    /\ OuterLive
    /\ outerLeased' = TRUE
    /\ UNCHANGED <<clock, revokedAt, innerLeased, innerExpiry,
                   effects, latestEffectAt, innerEffects, latestInnerEffectAt,
                   everExecuted>>

\* Nested reauthorization: work done under an existing authority asks for a
\* further one. The inner lease is chosen nondeterministically over the whole
\* clock range, and the guard -- not the choice -- is what keeps it inside the
\* outer. Generating only admissible values would make
\* `InnerNeverOutlivesOuter` true by construction and unfalsifiable.
IssueInnerLease ==
    /\ outerLeased
    /\ ~innerLeased
    /\ OuterLive
    /\ \E bound \in 0..MaxTime :
        /\ bound <= OuterExpiry
        /\ innerExpiry' = bound
    /\ innerLeased' = TRUE
    /\ UNCHANGED <<clock, revokedAt, outerLeased,
                   effects, latestEffectAt, innerEffects, latestInnerEffectAt,
                   everExecuted>>

RunOuterEffect ==
    /\ outerLeased
    /\ OuterLive
    /\ effects + innerEffects < MaxEffects
    /\ effects' = effects + 1
    /\ latestEffectAt' = clock
    /\ everExecuted' = TRUE
    /\ UNCHANGED <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
                   innerEffects, latestInnerEffectAt>>

\* The inner authority needs its own life *and* the outer's. It was derived
\* from the outer, so the outer lapsing is not something it can outlive -- the
\* opposite reading is how a nested grant becomes a way to keep working after
\* the authority behind it is gone.
RunInnerEffect ==
    /\ innerLeased
    /\ OuterLive
    /\ clock < innerExpiry
    /\ effects + innerEffects < MaxEffects
    /\ innerEffects' = innerEffects + 1
    /\ latestInnerEffectAt' = clock
    /\ everExecuted' = TRUE
    /\ UNCHANGED <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
                   effects, latestEffectAt>>

Next ==
    \/ Tick \/ Revoke
    \/ IssueOuterLease \/ IssueInnerLease
    \/ RunOuterEffect \/ RunInnerEffect

TypeOK ==
    /\ clock \in 0..MaxTime
    /\ revokedAt \in 0..NeverRevoked
    /\ outerLeased \in BOOLEAN
    /\ innerLeased \in BOOLEAN
    /\ innerExpiry \in 0..MaxTime
    /\ effects \in 0..MaxEffects
    /\ innerEffects \in 0..MaxEffects
    /\ latestEffectAt \in 0..MaxTime
    /\ latestInnerEffectAt \in 0..MaxTime
    /\ everExecuted \in BOOLEAN

\* No effect ran at or after the authority expired.
\*
\* Stated over the recorded moment rather than the current one: by the time an
\* invariant is evaluated the clock has usually moved on, so reading `clock`
\* would ask whether the authority is live *now* -- a different and much weaker
\* question than whether it was live when the effect ran.
NoEffectAfterExpiry ==
    (effects > 0) => (latestEffectAt < OuterExpiry)

\* No effect ran after the authority was withdrawn. Distinct from expiry: an
\* authority can be revoked long before its expiry, and a check that only
\* compares expiry admits every effect in between.
\*
\* WHY this is `<=` where `NoEffectAfterExpiry` is `<`, which looks like an
\* inconsistency and is the asymmetry between the two kinds of lapse. An expiry
\* is a boundary fixed in advance: the authority is not live at that moment, so
\* an effect there is unauthorized. A revocation is an event *recorded at* a
\* moment, and recording it does not reach back into the moment it names.
\* `docs/11-FAILURE_SEMANTICS.md` is explicit -- revocation blocks new work and
\* does not disable an already activated generation.
\*
\* TLC found this by running an effect and a revocation at the same instant,
\* with the effect first. Under `<` the recording retroactively unauthorized an
\* effect the world had already seen, which is the failure `RevocationIsForwardOnly`
\* names on the other axis. Strictness after the recording is not lost: `OuterLive`
\* requires `clock < revokedAt`, so once revoked nothing runs at that moment or
\* later, and `negative/EffectAfterRevocation.tla` removes that guard.
NoEffectAfterRevocation ==
    (effects > 0) => (latestEffectAt <= revokedAt)

\* Revocation is forward-only. It ends future authority; it does not reach back
\* and unmake an effect the world has already seen. `docs/02-CONSTITUTION.md`
\* law 12 puts the general form of this as: once delivered, artifact bytes
\* remain immutable, and corrections append.
RevocationIsForwardOnly ==
    everExecuted => (effects + innerEffects > 0)

\* A nested authority cannot outlive the one it was derived from. The same
\* monotonic-attenuation law `Delegation.tla` checks across the width axes,
\* here on the time axis, where it is the axis a lease actually runs out of.
InnerNeverOutlivesOuter ==
    innerLeased => (innerExpiry <= OuterExpiry)

\* A nested effect needed the outer authority live at the moment it ran, not
\* merely at the moment the inner lease was issued.
InnerEffectsNeedALiveOuter ==
    (innerEffects > 0)
        => /\ latestInnerEffectAt < OuterExpiry
           /\ latestInnerEffectAt <= revokedAt

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeOK
            /\ []NoEffectAfterExpiry
            /\ []NoEffectAfterRevocation
            /\ []RevocationIsForwardOnly
            /\ []InnerNeverOutlivesOuter
            /\ []InnerEffectsNeedALiveOuter

=============================================================================
