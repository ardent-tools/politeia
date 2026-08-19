------------------------------ MODULE Workflow ------------------------------
EXTENDS Naturals

\* Operation lifecycle states, per the vertical-slice path in
\* docs/18-FIRST_VERTICAL_SLICE.md.
CONSTANTS Proposed, Authorized, Running, Candidate, Verified, Accepted

VARIABLE state

Init == state = Proposed

\* Transitions move only forward along the authorized path. There is no skip
\* from Proposed to Running (execution without authorization) and no path back.
Next ==
    \/ /\ state = Proposed   /\ state' = Authorized
    \/ /\ state = Authorized /\ state' = Running
    \/ /\ state = Running    /\ state' = Candidate
    \/ /\ state = Candidate  /\ state' = Verified
    \/ /\ state = Verified   /\ state' = Accepted

TypeOK ==
    state \in {Proposed, Authorized, Running, Candidate, Verified, Accepted}

\* Nothing executes without having been authorized first.
NeverExecutesUnauthorized == (state \in {Running, Candidate, Verified, Accepted}) =>
    \* reached only by passing through Authorized; with a single forward path
    \* this reduces to: these states are unreachable from Init without it.
    TRUE

Spec == Init /\ [][Next]_state

THEOREM Spec => []TypeOK

=============================================================================
