------------------------- MODULE UnspentLeaseEffect -------------------------
\* Workflow with one extra edge: an effect that runs without spending its lease.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Every other precondition holds -- authorized, reserved, leased -- so the
\* three invariants that ask whether the operation was permitted are all
\* satisfied. What is missing is the record that this particular invocation
\* consumed the single-use grant, which is what makes the *next* one a
\* duplicate rather than the first.
\*
\* The state immediately after this edge carries one effect and an unspent
\* lease, which `AtMostOneEffectPerLease` cannot see: one effect is within its
\* bound. Only `EffectsRequireASpentLease` reaches it, which is what this
\* fixture exists to demonstrate.
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Leased /\ state' = Running
       /\ effects' = effects + 1
       /\ UNCHANGED <<authorized, reserved, leased, denied, leaseSpent>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
