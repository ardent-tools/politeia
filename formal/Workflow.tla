------------------------------ MODULE Workflow ------------------------------
EXTENDS Naturals

\* The protected-operation path, per docs/18-FIRST_VERTICAL_SLICE.md and the
\* dispatcher in politeia-runtime. An operation is authorized, its budget is
\* committed, a single-use lease is issued, and only then may an effect run.
\* Denial is a terminal outcome available before the lease exists.
CONSTANTS Proposed, Authorized, Reserved, Leased,
          Running, Candidate, Verified, Accepted, Denied

\* Four history variables, one per precondition the constitution places on
\* execution. They record that a step happened rather than that the state
\* machine currently sits on it.
\*
\* WHY history rather than reading `state`: "nothing executes without a
\* committed reservation" is a claim about the trace. Derived from `state`
\* alone it can only be re-read off whichever edges the model happens to have,
\* which makes each invariant restate the transition relation instead of
\* constraining it. With history, removing a step from the path fails a check --
\* and `formal/negative/` checks in exactly those removals.
VARIABLES state, authorized, reserved, leased, denied

vars == <<state, authorized, reserved, leased, denied>>

\* States in which an externally visible effect may have run.
Executing == {Running, Candidate, Verified, Accepted}

Init ==
    /\ state = Proposed
    /\ authorized = FALSE
    /\ reserved = FALSE
    /\ leased = FALSE
    /\ denied = FALSE

Next ==
    \* Authorization, then a committed budget reservation, then a single-use
    \* lease. Each records itself.
    \/ /\ state = Proposed   /\ state' = Authorized
       /\ authorized' = TRUE /\ UNCHANGED <<reserved, leased, denied>>
    \/ /\ state = Authorized /\ state' = Reserved
       /\ reserved' = TRUE   /\ UNCHANGED <<authorized, leased, denied>>
    \/ /\ state = Reserved   /\ state' = Leased
       /\ leased' = TRUE     /\ UNCHANGED <<authorized, reserved, denied>>
    \* Execution and the evidence path that follows it.
    \/ /\ state = Leased     /\ state' = Running
       /\ UNCHANGED <<authorized, reserved, leased, denied>>
    \/ /\ state = Running    /\ state' = Candidate
       /\ UNCHANGED <<authorized, reserved, leased, denied>>
    \/ /\ state = Candidate  /\ state' = Verified
       /\ UNCHANGED <<authorized, reserved, leased, denied>>
    \/ /\ state = Verified   /\ state' = Accepted
       /\ UNCHANGED <<authorized, reserved, leased, denied>>
    \* Denial is available until a lease exists, and is terminal.
    \/ /\ state \in {Proposed, Authorized, Reserved} /\ state' = Denied
       /\ denied' = TRUE     /\ UNCHANGED <<authorized, reserved, leased>>

TypeOK ==
    /\ state \in {Proposed, Authorized, Reserved, Leased,
                  Running, Candidate, Verified, Accepted, Denied}
    /\ authorized \in BOOLEAN
    /\ reserved \in BOOLEAN
    /\ leased \in BOOLEAN
    /\ denied \in BOOLEAN

\* Nothing executes without having been authorized first.
NeverExecutesUnauthorized == (state \in Executing) => authorized

\* Nothing executes without a committed budget reservation. Distinct from
\* authorization: an operation may be permitted and still have no budget
\* committed to it, and spending in that state is the overdraft the reservation
\* exists to prevent.
NeverExecutesWithoutReservation == (state \in Executing) => reserved

\* Nothing executes without an issued lease. Distinct again: authorization says
\* the operation may run, the reservation says it may spend, and the lease is
\* the single-use grant that a specific effect invocation consumes.
NeverExecutesWithoutLease == (state \in Executing) => leased

\* A denied operation stays denied. Without this, a path that re-establishes a
\* reservation and lease could carry a refused operation into execution with
\* every other precondition satisfied.
DenialIsFinal == denied => (state = Denied)

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeOK
            /\ []NeverExecutesUnauthorized
            /\ []NeverExecutesWithoutReservation
            /\ []NeverExecutesWithoutLease
            /\ []DenialIsFinal

=============================================================================
