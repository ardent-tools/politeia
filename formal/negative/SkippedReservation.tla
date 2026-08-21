-------------------------- MODULE SkippedReservation --------------------------
\* Workflow with one extra edge: authorization straight to a lease, skipping the
\* budget reservation.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* WHY it extends Workflow rather than copying it: a fixture that restates the
\* model drifts from it, and a drifted fixture tests something other than what it
\* claims while still going red for its own reasons. Extending keeps the states,
\* the transitions and every invariant identical by construction, so the single
\* added disjunct below is provably the only difference.
\*
\* This is available only because the defect is *additive*. A defect that removes
\* or weakens a definition cannot be expressed this way and needs a full copy --
\* see UncheckedAxis and SlackCap.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Authorized /\ state' = Leased
       /\ leased' = intent
       /\ UNCHANGED <<intent, authorized, reserved, denied, leaseSpent, effects, effectFor>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
