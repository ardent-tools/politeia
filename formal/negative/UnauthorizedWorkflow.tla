------------------------ MODULE UnauthorizedWorkflow ------------------------
\* Workflow with one extra edge: an operation that acquires a reservation and a
\* lease and runs, without ever being authorized.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* WHY it exists: a checking step that has only run against specifications which
\* satisfy their invariants has not demonstrated that it can report a violation.
\* It would go green against a `.cfg` naming no invariant, against a jar that
\* never ran, and against an invariant written as `TRUE` -- which is what this
\* repository's workflow invariant was before the change that added this file.
\*
\* The edge supplies a reservation and a lease so that only the authorization
\* invariant fails. An edge that supplied neither would trip three invariants at
\* once, and the fixture would stop isolating the one it is named after.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Proposed /\ state' = Running
       /\ reserved' = TRUE /\ leased' = TRUE /\ UNCHANGED <<authorized, denied, leaseSpent, effects>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
