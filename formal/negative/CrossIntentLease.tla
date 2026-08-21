------------------------- MODULE CrossIntentLease -------------------------
\* Workflow with one extra edge: an effect run under another intent's lease.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Every presence-shaped invariant holds. The operation was authorized, its
\* budget was committed, a lease was issued, and the lease was single-use and
\* spent exactly once. What the effect ran *for* is a different operation.
\*
\* This is the shape a dispatcher has when it treats a lease as a permission
\* bit: the checks it performs all ask whether authority exists, and none asks
\* whether this authority is the one that names this work. `docs/02-CONSTITUTION.md`
\* law 8 is the rule it breaks, and `ExecutesUnderItsOwnGrant` is the only
\* invariant here that can see it.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Leased /\ state' = Running
       /\ ~leaseSpent
       /\ leaseSpent' = TRUE /\ effects' = effects + 1
       /\ \E other \in Intents : other /= intent /\ effectFor' = other
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
