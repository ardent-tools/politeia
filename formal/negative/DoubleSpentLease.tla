---------------------------- MODULE DoubleSpentLease ----------------------------
\* Workflow with one extra edge: a retry that re-presents a lease without
\* checking whether it has already been spent.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* This is the defect a single-use lease exists to prevent, and it is invisible to
\* every other invariant here. The operation was authorized, its budget was
\* committed, a lease was issued, and it was never denied -- so authorization,
\* reservation, lease and denial invariants all hold on the very trace where the
\* same externally visible effect happens twice.
\*
\* The retry differs from the model's own retry edge by the single conjunct
\* `~leaseSpent`. That is the guard, and removing it is the whole bug: a retry
\* path that is correct except that it does not ask whether the work already ran.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state \in {Running, Candidate} /\ effects < MaxAttempts
       /\ state' = Running
       /\ leaseSpent' = TRUE /\ effects' = effects + 1
       /\ UNCHANGED <<authorized, reserved, leased, denied>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
