------------------------------ MODULE SkippedLease ------------------------------
\* Workflow with one extra edge: a committed reservation running an effect
\* without a lease ever being issued.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The operation is authorized and its budget is committed, so the two invariants
\* people reach for first both hold. What is missing is the single-use grant a
\* specific invocation consumes -- which is the difference between "this may run"
\* and "this run is the one that was permitted".
EXTENDS Workflow

BrokenNext ==
    \/ Next
    \/ /\ state = Reserved /\ state' = Running
       /\ UNCHANGED <<authorized, reserved, leased, denied>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
