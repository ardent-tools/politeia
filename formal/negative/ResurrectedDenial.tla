--------------------------- MODULE ResurrectedDenial ---------------------------
\* Workflow with one extra edge: a denied operation carried into execution by a
\* path that re-establishes its reservation and lease.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Every other precondition is satisfied on that path -- the operation was
\* authorized before it was refused, and the retry supplies a fresh reservation
\* and lease -- so authorization, reservation and lease invariants all hold. The
\* only thing wrong is that the refusal was not honoured, which is why a denial
\* needs an invariant of its own rather than being left to the shape of the
\* graph.
\*
\* The edge requires `authorized`, so the denial it resurrects is one that was
\* refused after authorization rather than before. Without that guard TLC could
\* reach the same state from an unauthorized denial and report the authorization
\* invariant instead, and the fixture would no longer isolate what it names.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Denied /\ authorized /= NoIntent /\ state' = Running
       /\ reserved' = intent /\ leased' = intent
       /\ UNCHANGED <<intent, authorized, denied, leaseSpent, effects, effectFor>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
