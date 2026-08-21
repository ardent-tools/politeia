------------------------ MODULE UnauthorizedWorkflow ------------------------
\* A deliberately broken copy of Workflow, checked in so the model checker can
\* be seen failing.
\*
\* WHY this file exists: a checking step that has only ever run against
\* specifications which satisfy their invariants has not demonstrated that it
\* can report a violation. It would go green against a misconfigured `.cfg`
\* naming no invariant, against a jar that never ran, and against an invariant
\* written as `TRUE` -- which is what this repository's workflow invariant was
\* before the change that added this file.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The only difference from `Workflow` is the third disjunct of `Next`: an edge
\* straight from Proposed to Running that never authorizes. That is exactly the
\* transition `NeverExecutesUnauthorized` exists to forbid.
EXTENDS Naturals

CONSTANTS Proposed, Authorized, Running, Candidate, Verified, Accepted

VARIABLES state, authorized

vars == <<state, authorized>>

Executing == {Running, Candidate, Verified, Accepted}

Init == state = Proposed /\ authorized = FALSE

Next ==
    \/ /\ state = Proposed   /\ state' = Authorized /\ authorized' = TRUE
    \/ /\ state = Authorized /\ state' = Running    /\ UNCHANGED authorized
    \* The planted defect: execution without authorization.
    \/ /\ state = Proposed   /\ state' = Running    /\ UNCHANGED authorized
    \/ /\ state = Running    /\ state' = Candidate  /\ UNCHANGED authorized
    \/ /\ state = Candidate  /\ state' = Verified   /\ UNCHANGED authorized
    \/ /\ state = Verified   /\ state' = Accepted   /\ UNCHANGED authorized

TypeOK ==
    /\ state \in {Proposed, Authorized, Running, Candidate, Verified, Accepted}
    /\ authorized \in BOOLEAN

NeverExecutesUnauthorized == (state \in Executing) => authorized

Spec == Init /\ [][Next]_vars

=============================================================================
