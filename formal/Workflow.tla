------------------------------ MODULE Workflow ------------------------------
EXTENDS Naturals

\* Operation lifecycle states, per the vertical-slice path in
\* docs/18-FIRST_VERTICAL_SLICE.md.
CONSTANTS Proposed, Authorized, Running, Candidate, Verified, Accepted

\* `authorized` is history rather than lifecycle: it records that the
\* authorization step occurred, so the safety property below can be stated
\* about the trace instead of about the shape of the transition relation.
\*
\* WHY it exists: "nothing executes unauthorized" is not a fact about the
\* current state. Read off `state` alone it can only be re-derived from the
\* edges the model happens to have, which makes the invariant restate the
\* specification rather than constrain it. With history it becomes falsifiable
\* -- add an edge into an executing state that does not authorize, and the
\* invariant fails. `formal/negative/` checks in exactly that edge and requires
\* the checker to report it.
VARIABLES state, authorized

vars == <<state, authorized>>

Executing == {Running, Candidate, Verified, Accepted}

Init == state = Proposed /\ authorized = FALSE

\* Transitions move only forward along the authorized path. There is no skip
\* from Proposed to Running (execution without authorization) and no path back.
Next ==
    \/ /\ state = Proposed   /\ state' = Authorized /\ authorized' = TRUE
    \/ /\ state = Authorized /\ state' = Running    /\ UNCHANGED authorized
    \/ /\ state = Running    /\ state' = Candidate  /\ UNCHANGED authorized
    \/ /\ state = Candidate  /\ state' = Verified   /\ UNCHANGED authorized
    \/ /\ state = Verified   /\ state' = Accepted   /\ UNCHANGED authorized

TypeOK ==
    /\ state \in {Proposed, Authorized, Running, Candidate, Verified, Accepted}
    /\ authorized \in BOOLEAN

\* Nothing executes without having been authorized first.
NeverExecutesUnauthorized == (state \in Executing) => authorized

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeOK /\ []NeverExecutesUnauthorized

=============================================================================
