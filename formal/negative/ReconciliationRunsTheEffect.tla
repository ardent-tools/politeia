--------------------- MODULE ReconciliationRunsTheEffect ---------------------
\* EffectAmbiguity with one extra edge: a reconciliation that produces an
\* effect.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Reconciliation is available precisely when retrying is not, because it is
\* read-only. An implementation that reaches the target by reissuing the work
\* and observing what happens has built a retry and named it a read -- and has
\* made it available in exactly the state where the retry is forbidden.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ delivery /= NotIssued
       /\ resolution = Unresolved
       /\ ~reconciled
       /\ effects < MaxEffects
       /\ reconciled' = TRUE
       /\ outcome' = Ran
       /\ resolution' = Resolved
       /\ effects' = effects + 1
       /\ UNCHANGED <<delivery, replay, overlap, receiptBound,
                      targetObserved, compensated, grants>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
